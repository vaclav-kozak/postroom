"""Folder alias resolution against an IMAP `list_folders()` result.

`resolve_folder` takes the list of `(flags, delimiter, name)` tuples that
`imapclient.IMAPClient.list_folders()` returns and resolves a user-facing
alias (or literal folder name) to the actual mailbox name to select.
"""

ALIASES = ("inbox", "sent", "drafts", "archive", "all", "junk", "trash")

_NOSELECT = (b"\\Noselect", b"\\NonExistent")

# RFC 6154 SPECIAL-USE attributes mapped to our alias names.
_SPECIAL_USE = {
    b"\\Sent": "sent",
    b"\\Drafts": "drafts",
    b"\\Archive": "archive",
    b"\\All": "all",
    b"\\Junk": "junk",
    b"\\Trash": "trash",
}

NAME_FALLBACK = {
    "sent": ["sent", "sent items", "sent messages", "sent mail", "odeslané", "odeslaná pošta"],
    "drafts": ["drafts", "koncepty", "rozepsané"],
    "archive": ["archive", "archiv"],
    "junk": ["junk", "spam", "nevyžádaná pošta"],
    "trash": ["trash", "koš", "deleted items", "deleted messages"],
    "all": ["all mail", "všechny zprávy"],
}


class FolderNotFound(Exception):
    def __init__(self, wanted: str | None):
        self.wanted = wanted
        super().__init__(f"folder not found: {wanted!r}")


def special_use_of(flags: tuple[bytes, ...]) -> str | None:
    """Return the alias (e.g. "sent") for a folder's SPECIAL-USE flag, if any."""
    for flag in flags:
        alias = _SPECIAL_USE.get(flag)
        if alias is not None:
            return alias
    return None


def _is_selectable(flags: tuple[bytes, ...]) -> bool:
    return not any(f in _NOSELECT for f in flags)


def resolve_folder(
    folders: list[tuple[tuple[bytes, ...], bytes | None, str]],
    wanted: str | None,
    *,
    special_use_first: bool = False,
) -> str:
    """The mailbox name for `wanted`: INBOX, an exact (then case-insensitive) name, or an
    alias (sent, drafts, ...) by its SPECIAL-USE flag, then by known folder names.

    With `special_use_first`, an alias is resolved by its SPECIAL-USE flag before any
    folder merely named like it (create_draft: a stray "Drafts" folder must not win over
    the account's real \\Drafts).
    """
    if wanted is None or wanted.lower() == "inbox":
        for flags, _delim, name in folders:
            if name.upper() == "INBOX" and _is_selectable(flags):
                return name
        raise FolderNotFound(wanted)

    selectable = [(flags, delim, name) for flags, delim, name in folders if _is_selectable(flags)]

    alias = wanted.lower()
    if special_use_first and alias in ALIASES:
        for flags, _delim, name in selectable:
            if special_use_of(flags) == alias:
                return name

    # Exact name match: case-sensitive first, then case-insensitive.
    for _flags, _delim, name in selectable:
        if name == wanted:
            return name
    for _flags, _delim, name in selectable:
        if name.lower() == wanted.lower():
            return name

    if alias in ALIASES:
        # First folder whose SPECIAL-USE flag matches the alias.
        for flags, _delim, name in selectable:
            if special_use_of(flags) == alias:
                return name

        # Name fallback: match the last path segment (split on the delimiter)
        # case-insensitively against the known localized/plain names.
        candidates = NAME_FALLBACK.get(alias, [])
        for flags, delim, name in selectable:
            delim_str = delim.decode() if delim else None
            last_segment = name.rsplit(delim_str, 1)[-1] if delim_str else name
            if last_segment.lower() in candidates:
                return name

    raise FolderNotFound(wanted)
