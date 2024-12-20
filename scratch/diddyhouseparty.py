print("     /\\")
print("    /  \\")
print("   /____\\")
print("   |    |")
print("   |____|")

n = 5 # no. of levels
base = 2*n
pranav = base+2
r = n+1
space = ""
roof = ""
walls = "|"
floor = "|"
for i in range(1,base+1):
    floor += "_"
    walls += " "
floor += "|"
walls += "|"
for i in range(1, r):
    roof = (f"/{space}\\")
    print(f"{roof:^{pranav}}")
    space += "  "
print(f"/{floor[1:-1]}\\") # roof base!!!
for i in range(1,n):
    print(walls)
print(floor)
    
    
# hi
#x = "|"
#print(f"{x:^13}") # NOTE: This will print 'hi     
