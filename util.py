import os
import shutil
import tempfile
from zipfile import ZipFile, ZIP_STORED, ZipInfo

"""
Borrowed from: https://github.com/PortSwigger/office-open-xml-editor/blob/master/UpdateableZipFile.py
"""
class UpdateableZipFile(ZipFile):
    class DeleteMarker(object):
        pass

    def __init__(
        self, file, mode="r", compression=ZIP_STORED, allowZip64=False
    ):
        super(UpdateableZipFile, self).__init__(
            file, mode=mode, compression=compression, allowZip64=allowZip64
        )
        self._replace = {}
        self._allow_updates = False

    def writestr(self, zinfo_or_arcname, bytes, compress_type=None):
        if isinstance(zinfo_or_arcname, ZipInfo):
            name = zinfo_or_arcname.filename
            if self._allow_updates and name in self.namelist():
                temp_file = self._replace[name] = self._replace.get(
                    name, tempfile.TemporaryFile()
                )
                temp_file.write(bytes)
        else:
            super(UpdateableZipFile, self).writestr(
                zinfo_or_arcname, bytes, compress_type=compress_type
            )

    def write(self, filename, arcname=None, compress_type=None):
        arcname = arcname or filename
        if self._allow_updates and arcname in self.namelist():
            temp_file = self._replace[arcname] = self._replace.get(
                arcname, tempfile.TemporaryFile()
            )
            with open(filename, "rb") as source:
                shutil.copyfileobj(source, temp_file)
        else:
            super(UpdateableZipFile, self).write(
                filename, arcname=arcname, compress_type=compress_type
            )

    def __enter__(self):
        self._allow_updates = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            super(UpdateableZipFile, self).__exit__(exc_type, exc_val, exc_tb)
            if len(self._replace) > 0:
                self._rebuild_zip()
        finally:
            self._close_all_temp_files()
            self._allow_updates = False

    def _close_all_temp_files(self):
        for temp_file in self._replace.values():
            if hasattr(temp_file, "close"):
                temp_file.close()

    def remove_file(self, path):
        self._replace[path] = self.DeleteMarker()

    def _rebuild_zip(self):
        tempdir = tempfile.mkdtemp()
        try:
            temp_zip_path = os.path.join(tempdir, "new.zip")
            with ZipFile(self.filename, "r") as zip_read:
                with ZipFile(
                    temp_zip_path,
                    "w",
                    compression=self.compression,
                    allowZip64=self._allowZip64,
                ) as zip_write:
                    for item in zip_read.infolist():
                        replacement = self._replace.get(item.filename, None)
                        if isinstance(replacement, self.DeleteMarker):
                            del self._replace[item.filename]
                            continue
                        elif replacement is not None:
                            del self._replace[item.filename]
                            replacement.seek(0)
                            data = replacement.read()
                            replacement.close()
                        else:
                            data = zip_read.read(item.filename)
                        zip_write.writestr(item, data)
            shutil.move(temp_zip_path, self.filename)
        finally:
            shutil.rmtree(tempdir)
