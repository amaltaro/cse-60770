import itertools

def generate_combinations(length):
    characters = string.ascii_letters + string.digits + '&@#'
    for combination in itertools.product(characters, repeat=length):
        yield ''.join(combination)