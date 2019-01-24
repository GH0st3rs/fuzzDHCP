import sys
from random import randint, sample
import string


class BinaryFuzzer():
    """
    Fuzzer that produces unstructured binary output
    """

    def __init__(self, min_length, max_length=None):
        self._min_length = min_length
        self._max_length = max_length

    @property
    def min_length(self):
        return self._min_length

    @property
    def max_length(self):
        return self._max_length

    def generate(self):
        data = []
        start = self.min_length
        end = 0
        if self.max_length is not None:
            end = randint(start, self.max_length)
        else:
            end = randint(start, sys.maxsize)
        for i in range(start, end):
            data.append(randint(0, 255))
        # self._cases.append(bytes(data))
        return bytes(data)


class AlphaNumericFuzzer():
    """
    A fuzzer that produces unstructured alphanumeric output
    """

    def __init__(self, min_length, max_length):
        self._min_length = min_length
        self._max_length = max_length
        self._alphabet = set(string.ascii_letters + string.digits + string.punctuation)

    @property
    def min_length(self):
        return self._min_length

    @property
    def max_length(self):
        return self._max_length

    def generate(self):
        data = []
        start = self.min_length
        end = self.max_length
        for i in range(start, end):
            data.append(sample(self._alphabet, 1)[0])
        # self._cases.append("".join(data))
        return "".join(data)


class NumericFuzzer():
    """
    A fuzzer that produces unstructured numeric output
    """

    def __init__(self, min_length, max_length):
        self._min_length = min_length
        self._max_length = max_length
        self._alphabet = set(string.digits)

    @property
    def min_length(self):
        return self._min_length

    @property
    def max_length(self):
        return self._max_length

    def generate(self):
        data = []
        start = self.min_length
        end = self.max_length
        for i in range(start, end):
            data.append(sample(self._alphabet, 1)[0])
        # self._cases.append("".join(data))
        return "".join(data)
