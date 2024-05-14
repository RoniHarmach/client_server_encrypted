import functools
import tkinter as tk

from user_login_protocol import UserLoginProtocol


class LoginApp:
    user_login_protocol: UserLoginProtocol = None
    login_callback = None
    login_result_label = None
    sign_up_result_label = None

    def __init__(self, user_login_protocol, login_callback):
        self.login_frame = None
        self.sign_up_frame = None
        self.user_login_protocol = user_login_protocol
        self.root = self.root = tk.Tk()
        self.login_callback = login_callback

    def sign_up_clicked(self, user, email, password, reenter_password):
        if password.get() != reenter_password.get():
            message = f"Passwords don't match"
            fg = "red"
        else:
            sign_up_response = self.user_login_protocol.sign_up(user.get(), email.get(), password.get())
            if sign_up_response.result:
                message = "Sign Up Succeeded!"
                fg = "green"
            else:
                message = f"Sign Up Failed: {sign_up_response.error}"
                fg = "red"

        if self.sign_up_result_label is not None:
            self.sign_up_result_label.config(text=message, fg=fg)
        else:
            self.sign_up_result_label = tk.Label(self.sign_up_frame, text=message, fg=fg)
            self.sign_up_result_label.pack()

    def login_clicked(self, user, password):
        print(f"email:{user.get()}, pass:{password.get()}")
        login_response = self.user_login_protocol.login(user.get(), password.get())

        if login_response.result:
            message = "Login Succeeded!"
            fg = "green"
        else:
            message = f"Login Failed: {login_response.error}"
            fg = "red"

        if self.login_result_label is not None:
            self.login_result_label.config(text=message, fg=fg)
        else:
            self.login_result_label = tk.Label(self.login_frame, text=message, fg=fg)
            self.login_result_label.pack()

        label = tk.Label(self, text="You are now in the next frame", fg="blue", cursor="hand2")
        label.pack()
        label.bind("<Button-1>", lambda event: master.show_frame(InitialFrame))


    def create_sign_up_screen(self):
        self.root.title("Sign-Up")
        self.root.geometry("400x250")
        self.sign_up_frame = tk.Frame(self.root)
        self.sign_up_frame.pack()

        user = tk.StringVar()
        email = tk.StringVar()
        password = tk.StringVar()
        reenter_password = tk.StringVar()

        user_label = tk.Label(self.sign_up_frame, text="User Name:")
        user_label.pack(fill='x', expand=True)

        user_entry = tk.Entry(self.sign_up_frame, textvariable=user)
        user_entry.pack(fill='x', expand=True)
        user_entry.focus()

        email_label = tk.Label(self.sign_up_frame, text="Email:")
        email_label.pack(fill='x', expand=True)

        email_entry = tk.Entry(self.sign_up_frame, textvariable=email)
        email_entry.pack(fill='x', expand=True)

        # password
        password_label = tk.Label(self.sign_up_frame, text="Password:")
        password_label.pack(fill='x', expand=True)

        password_entry = tk.Entry(self.sign_up_frame, textvariable=password, show="*")
        password_entry.pack(fill='x', expand=True)

        reenter_password_label = tk.Label(self.sign_up_frame, text="Reenter Password:")
        reenter_password_label.pack(fill='x', expand=True)

        reenter_password_entry = tk.Entry(self.sign_up_frame, textvariable=reenter_password, show="*")
        reenter_password_entry.pack(fill='x', expand=True)

        partial_func = functools.partial(self.sign_up_clicked, user, email, password, reenter_password)

        # login button
        sign_up_button = tk.Button(self.sign_up_frame, text="Sign Up", command=partial_func)
        sign_up_button.pack(fill='x', expand=True, pady=10)

    def create_login_screen(self):
        self.root.title("Login")
        self.root.geometry("400x250")
        self.login_frame = tk.Frame(self.root)
        self.login_frame.pack()

        user = tk.StringVar()
        password = tk.StringVar()

        user_label = tk.Label(self.login_frame, text="User Name:")
        user_label.pack(fill='x', expand=True)

        email_entry = tk.Entry(self.login_frame, textvariable=user)
        email_entry.pack(fill='x', expand=True)
        email_entry.focus()

        # password
        password_label = tk.Label(self.login_frame, text="Password:")
        password_label.pack(fill='x', expand=True)

        password_entry = tk.Entry(self.login_frame, textvariable=password, show="*")
        password_entry.pack(fill='x', expand=True)

        partial_func = functools.partial(self.login_clicked, user, password)

        # login button
        login_button = tk.Button(self.login_frame, text="Login", command=partial_func)
        login_button.pack(fill='x', expand=True, pady=10)

    def run(self):
        self.create_login_screen()
        #self.create_sign_up_screen()
        self.root.mainloop()
