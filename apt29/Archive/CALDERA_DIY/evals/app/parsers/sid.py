from app.objects.secondclass.c_relationship import Relationship
from app.utility.base_parser import BaseParser
import re


class Parser(BaseParser):

    def __init__(self, parser_info):
        super().__init__(parser_info)
        self.mappers = parser_info['mappers']
        self.used_facts = parser_info['used_facts']

    def sid_parser(self, text):
        if text and len(text) > 0:
            value = re.search(r'S-(\d-?){1,34}', text)
            if value:
                return [value.group(0)[:-1]]
            else:
                print("[!] Error parsing SID")

    def parse(self, blob):
        relationships = []
        try:
            parse_data = self.sid_parser(blob)
            for match in parse_data:
                for mp in self.mappers:
                    relationships.append(
                        Relationship(source=(mp.source, match),
                                     edge=mp.edge,
                                     target=(mp.target, None)
                                     )
                    )
        except Exception:
            import pdb; pdb.set_trace()
            pass
        return relationships
