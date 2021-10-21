import matplotlib as plt

present = []
slim = []

with open('../PRESENT/PRESENT-result.csv', 'r') as p:
    present = p.read().split(',')
    present[-1] = present[-1][:-1]

with open('../SLIM/SLIM-result.csv', 'r') as s:
    slim = s.read().split(',')
    slim[-1] = slim[-1][:-1]

    