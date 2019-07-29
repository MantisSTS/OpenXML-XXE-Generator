import os

filetypes = {
    "docx": {
        "ooxml": True,
        "template": os.path.join("samples", "docx", "template.docx"),
    },
    "xlsx": {
        "ooxml": True,
        "template": os.path.join("samples", "xlsx", "template.xlsx"),
    },
    "odg": {"ooxml": True, "template": os.path.join("samples", "template.odg")},
    "odp": {"ooxml": True, "template": os.path.join("samples", "template.odp")},
    "ods": {"template": os.path.join("samples", "template.ods"), "ooxml": True},
    "odt": {"template": os.path.join("samples", "template.odt"), "ooxml": True},
    "pptx": {
        "template": os.path.join("samples", "template.pptx"),
        "ooxml": True,
    },
    "svg": {
        "template": os.path.join("samples", "template.svg"),
        "ooxml": False,
    },
    "xml": {
        "template": os.path.join("samples", "template.ods"),
        "ooxml": False,
    },
}
