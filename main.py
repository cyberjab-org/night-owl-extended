import json
from NightOwl import fileChecker

report = fileChecker("Test Subject.eml", {})
print(json.dumps(report))
