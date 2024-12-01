f = open("some_pdf.pdf", "rb")
data = f.read()
print(data)

x = open("uhhh.pdf", "wb")
x.write(data)
x.close()