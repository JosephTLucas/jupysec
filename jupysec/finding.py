from dataclasses import dataclass
from uuid import uuid4, UUID
from jinja2 import Environment, FileSystemLoader

@dataclass
class Finding:
    category: str = "Uncategorized"
    source_doc: str = ""
    source_text: str = ""
    source_details: str = ""
    remediation: str = ""
    uuid: UUID = uuid4()