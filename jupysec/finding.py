from dataclasses import dataclass
import uuid

@dataclass
class Finding:
    category: str = "Uncategorized"
    source_doc: str = ""
    source_text: str = ""
    source_details: str = ""
    remediation: str = ""
    uuid = None

    def __post_init__(self):
        self.uuid = uuid.uuid4()