@staticmethod


def intersect(space1, space2):
    if space1 is None or space2 is None:  # if space is empty
        return None
    result_space = ''
    for i in range(0, len(space1)):
        if space1[i] == space2[i]:
            result_space += space1[i]
        elif ord(space1[i]) + ord(space2[i]) == 97:  # 1 0 or 0 1
            return None
        elif space1[i] == '*':
            result_space += space2[i]
        else:
            result_space += space1[i]

    return result_space


class Space:
    def __init__(self, area=None):
        if area is None:
            self.areas = []
        else:
            self.areas = [area]

    def plus(self, area):
        for a in self.areas:
            if a == area:
                return

        self.areas.append(area)

    def minus(self, area):
        if area in self.areas:
            self.areas.remove(area)
        else:
            # TODO: remove area using algebra
            return

    def multiply(self, area):
        for i in range(len(self.areas)):
            self.areas[i] = intersect(self.areas[i], area)

        self.areas.remove(None)
