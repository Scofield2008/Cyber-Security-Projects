from tkinter import *

def subtract():
    num1 = int(entry1.get())
    num2 = int(entry2.get())
    result = num1 - num2
    label_result.config(text="Result: " + str(result))

root = Tk()
root.title("Subtract Two Numbers")

entry1 = Entry(root)
entry1.pack()

entry2 = Entry(root)
entry2.pack()

btn = Button(root, text="Subtract", command=subtract)
btn.pack()

label_result = Label(root, text="Result:")
label_result.pack()

root.mainloop()
