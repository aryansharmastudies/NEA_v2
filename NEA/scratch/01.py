import json

class human():
    def __init__(self, name, gender):
        self.name.surname = name
        self.gender = gender
        self.age = 17
        #surname = 'surname'
        #setattr(self.name, surname, 'sharma')

    def tojson(self):
        return json.dumps(self,default=lambda o: o.__dict__, sort_keys=True, indent=4)
    
aryan = human('aryan', 'male')
print(f'{aryan}')
print(f'{aryan.gender}')
print(f'{aryan.age}')
#aryan.name.surname ='sharma'

print(aryan.tojson())

del aryan
#aryan = human('anjali', 'female')


print(aryan.tojson())