from tkinter import *
from id import get_id
tk=Tk()


def print_input(*args):
    for entry in entries:
        print(entry.get())
    print(get_id())    
    


L1 = Label(tk, text = "User Name")
L1.pack()
entries = []
#entries = [Entry(tk) for _ in range(2)]
# for entry in entries:
#     entry.pack()

E1 = Entry(tk)
entries.append(E1)
E1.pack()

L2 = Label(tk, text = "Password")
L2.pack()
E2 = Entry(tk, show="*")
entries.append(E2)
E2.pack()


# tb=Entry(tk) #Both Entry1 and Entry2 are stored in the same variable: tb

#tb.pack()
#Entry 2
#Button
btn = Button(tk, text="Print", command=print_input)
btn.pack()
tk.mainloop()

# top = Tk()
# L1 = Label(top, text="User Name")
# L1.pack( side = LEFT)
# E1 = Entry(top, bd =5)
# E1.pack(side = RIGHT)

# top.mainloop()