import os
import sys


def initialization():

    print("Hello World!")

    return 0


def cleanup():

    print("Bye-bye World!")


module_init(initialization)
module_exit(cleanup)

MODULE_LICENSE("GPL")
