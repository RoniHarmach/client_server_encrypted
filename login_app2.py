import tkinter as tk

class MyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Link Example")
        self.current_frame = None

        # Create the initial frame
        self.show_frame(LoginFrame)

    def show_frame(self, frame_class):
        # Destroy the current frame if it exists
        if self.current_frame:
            self.current_frame.destroy()

        # Create and display the new frame
        self.current_frame = frame_class(self)
        self.current_frame.pack()

class LoginFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        master.title("Login")
        master.geometry("400x250")


        user = tk.StringVar()
        password = tk.StringVar()

        user_label = tk.Label(self, text="User Name:")
        user_label.pack(fill='x', expand=True)

        user_entry = tk.Entry(self, textvariable=user)
        user_entry.pack(fill='x', expand=True)
        user_entry.focus()

        # password
        password_label = tk.Label(self, text="Password:")
        password_label.pack(fill='x', expand=True)

        password_entry = tk.Entry(self, textvariable=password, show="*")
        password_entry.pack(fill='x', expand=True)

        label = tk.Label(self, text="Sign Up", fg="blue", cursor="hand2")
        label.pack()
        label.bind("<Button-1>", lambda event: master.show_frame(SignUpFrame))

class SignUpFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master)

        master.title("Sign Up")
        master.geometry("400x250")

        user = tk.StringVar()
        email = tk.StringVar()
        password = tk.StringVar()
        reenter_password = tk.StringVar()

        user_label = tk.Label(self, text="User Name:")
        user_label.pack(fill='x', expand=True)

        user_entry = tk.Entry(self, textvariable=user)
        user_entry.pack(fill='x', expand=True)
        user_entry.focus()

        email_label = tk.Label(self, text="Email:")
        email_label.pack(fill='x', expand=True)

        email_entry = tk.Entry(self, textvariable=email)
        email_entry.pack(fill='x', expand=True)

        # password
        password_label = tk.Label(self, text="Password:")
        password_label.pack(fill='x', expand=True)

        password_entry = tk.Entry(self, textvariable=password, show="*")
        password_entry.pack(fill='x', expand=True)

        reenter_password_label = tk.Label(self, text="Reenter Password:")
        reenter_password_label.pack(fill='x', expand=True)

        reenter_password_entry = tk.Entry(self, textvariable=reenter_password, show="*")
        reenter_password_entry.pack(fill='x', expand=True)

        label = tk.Label(self, text="Login", fg="blue", cursor="hand2")
        label.pack()
        label.bind("<Button-1>", lambda event: master.show_frame(LoginFrame))

if __name__ == "__main__":
    app = MyApp()
    app.mainloop()
