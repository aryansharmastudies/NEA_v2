# main program.
# client program which connects to file-server and checks for missing files.
def convert_to_binary(file_name = "text"):
    r = open(f"{file_name}.txt", "rb")
    data = r.read()
    print(data)
convert_to_binary()