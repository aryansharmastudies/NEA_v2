# as an alternate to
# f = open("test.txt", "r")
# print(f.read())

# The with statement is used to wrap the execution of a block of code.
# what this means is that the with statement will automatically take care of closing the file for you.

with open("with_text.txt", "r") as f:
    print(f.read())

# with automatically closes the file.