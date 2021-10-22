import matplotlib as plt

present = []
slim = []

with open('../PRESENT/PRESENT-times.csv', 'r') as p:
    present = p.read().split(',')
    # present[-1] = present[-1][:-1]

with open('../SLIM/SLIM-times.csv', 'r') as s:
    slim = s.read().split(',')
    # slim[-1] = slim[-1][:-1]

with open('../TWINE/TWINE-times.csv', 'r') as s:
    twine = s.read().split(',')
    # twine[-1] = slim[-1][:-1]

print(twine)
print(slim)
print(present)

    