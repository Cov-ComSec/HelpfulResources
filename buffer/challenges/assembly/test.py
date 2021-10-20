from pwn import *

context.arch = "amd64"

def test_1():
    x = int(input("Enter x: ").strip())
    y = int(input("Enter y: ").strip())
    z = int(input("Enter z: ").strip())
    a = int(input("Enter a: ").strip())
    expected = int((x * y) / z + a)
    p = process("task1.elf")
    actual = p.poll(block=True)
    print(f"Expected result: {expected}")
    print(f"Actual result: {actual}")
    if actual == expected:  print("Passed\nFlag: cueh{my_f1rst_4ss3mbly!!")
    else:   print("Fail. No flag for you")

def test_2():
    expected = 4*4*4
    p = process("task2.elf")
    actual = p.poll(block=True)
    print(f"Expected result: {expected}")
    print(f"Actual result: {actual}")
    if actual == expected:  print("Passed\nFlag: cueh{cub1ng_f0r_d4ys!!")
    else:   print("Fail. No flag for you")

def test_3():
    x = 11906
    y = 4
    expected =11
    p = process("task3.elf")
    actual = p.poll(block=True)
    print(f"Expected result: {expected}")
    print(f"Actual result: {actual}")
    if actual == expected:  print("Passed\nFlag: cueh{cub1ng_f0r_d4ys!!")
    else:   print("Fail. No flag for you")


if __name__ == "__main__":
    menu ="""Do you want to test:
1: Task 1
2: Task 2
3: Task 3
> """
    task = int(input(menu).strip())
    if task == 1:
        test_1()
    elif task == 2:
        test_2()
    elif task == 3:
        test_3()
    else:
        print("Enter valid test number")