import random
class VerificationCodeCreator:

    @staticmethod
    def create_code():
        random_number = random.randint(100000000, 1000000000)
        return random_number
