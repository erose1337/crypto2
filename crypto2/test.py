if __name__ == "__main__":
    import encryption
    import function
    import kem
    import signature
    for module in (encryption, function, kem, signature):
        for name in dir(module):
            if name[:4] == "test":
                test = getattr(module, name)
                try:
                    test()
                except TypeError:
                    print("Unable to run test {}.'{}'".format(module.__name__, name))
