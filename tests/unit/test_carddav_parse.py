from postroom.dav.carddav import parse_vcards

CARDS = """BEGIN:VCARD\r
VERSION:3.0\r
FN:Jan Novák\r
N:Novák;Jan;;;\r
EMAIL;TYPE=work:jan@example.com\r
EMAIL:jan@example.net\r
TEL;TYPE=cell:+420 777 000 111\r
ORG:Firma s.r.o.\r
END:VCARD\r
BEGIN:VCARD\r
VERSION:3.0\r
N:Svobodová;Eva;;;\r
EMAIL:eva@x.example.com\r
END:VCARD\r
BEGIN:VCARD\r
garbage\r
END:VCARD\r
"""


def test_parse_vcards():
    cards = parse_vcards(CARDS)
    assert cards[0] == {
        "name": "Jan Novák",
        "emails": ["jan@example.com", "jan@example.net"],
        "phones": ["+420 777 000 111"],
        "organization": "Firma s.r.o.",
        "nickname": None,
    }
    assert cards[1]["name"] == "Eva Svobodová" and cards[1]["emails"] == ["eva@x.example.com"]
    assert len(cards) == 2
