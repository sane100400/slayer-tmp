import random

def shuffle_quiz_options(options: list) -> list:
    shuffled = options.copy()
    random.shuffle(shuffled)
    return shuffled

def pick_random_winner(participants: list) -> str:
    return random.choice(participants)

def roll_dice() -> int:
    return random.randint(1, 6)
