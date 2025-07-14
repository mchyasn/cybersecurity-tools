import base64

text = "Layered secret"
first = base64.b64encode(text.encode()).decode()
second = base64.b64encode(first.encode()).decode()
print(second)
