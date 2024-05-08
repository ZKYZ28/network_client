import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

class MainWindow:
    def __init__(self, controller):
        self.controller = controller
        self.controller.register_window(self)
        self.root = tk.Tk()
        self.root.title("Murmur™ Client - © Louis SWINNEN 2023")
        self.root.config(bd=5)
        self.host = tk.StringVar()
        self.passw = tk.StringVar()
        self.login = tk.StringVar()
        self.tls = tk.BooleanVar()
        self.port = tk.IntVar()
        self.message = tk.StringVar()
        self.draw_window()

    def start_main_loop(self):
        self.tf_host.focus()
        self.root.mainloop()

    def draw_window(self):
        self.draw_top_pane()
        self.draw_center_pane()
        self.draw_footer_pane()
        self.not_connected_mode()

    def draw_top_pane(self):
        top_pane = ttk.LabelFrame(self.root, padding=(3, 3, 12, 12), text=" Connection to ChatServer ")
        top_pane.pack(fill=tk.X)
        top_pane.columnconfigure(1, weight=1)

        ttk.Label(top_pane, text="Host:").grid(row=0, column=0, sticky=tk.E)
        self.tf_host = ttk.Entry(top_pane, textvariable=self.host)
        self.tf_host.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)

        ttk.Label(top_pane, text="Port:").grid(row=0, column=2, sticky=tk.E)
        self.tf_port = ttk.Entry(top_pane, textvariable=self.port)
        self.tf_port.grid(row=0, column=3, sticky=tk.EW, padx=5, pady=2)

        ttk.Label(top_pane, text="Login:").grid(row=1, column=0, sticky=tk.E)
        self.tf_login = ttk.Entry(top_pane, textvariable=self.login)
        self.tf_login.grid(row=1,column=1, sticky=tk.EW, padx=5, pady=5)

        ttk.Label(top_pane, text="Password:").grid(row=1, column=2, sticky=tk.E)
        self.tf_password = ttk.Entry(top_pane, show="*", textvariable=self.passw)
        self.tf_password.grid(row=1,column=3, sticky=tk.EW, padx=5, pady=2)

        inner_frame = ttk.Frame(top_pane)
        inner_frame.grid(row=2, column=0, columnspan=4, sticky=tk.NSEW)
        inner_frame.columnconfigure(1,weight=1)

        ttk.Label(inner_frame, text="Security:").grid(row=0, column=0, sticky=tk.E)
        self.cb_tls = ttk.Checkbutton(inner_frame, text="with SSL/TLS", variable=self.tls)
        self.cb_tls.grid(row=0, column=1, padx=5, pady=2, sticky=tk.W)
        self.bt_register = ttk.Button(inner_frame, text="Register", command=self.register)
        self.bt_register.grid(row=0, column=2, padx=5, pady=2,sticky=tk.E)
        self.bt_connect = ttk.Button(inner_frame, text="Connect", command=self.connect)
        self.bt_connect.grid(row=0, column=3, padx=5, pady=2, sticky=tk.E)

    def draw_center_pane(self):
        title_pane = ttk.Frame(self.root, padding=(5, 0, 5, 0))
        ttk.Label(title_pane, text="Messages:").grid(row=0, column=0, sticky=tk.E)
        title_pane.pack(fill=tk.X)
        center_pane = ttk.Frame(self.root, padding=(5, 0, 5, 0))
        center_pane.pack(fill=tk.BOTH, expand=True)
        #center_pane.columnconfigure(1, weight=1)

        self.text_box = tk.Text(center_pane,  wrap = "word")
        ys = ttk.Scrollbar(center_pane, orient = 'vertical', command = self.text_box.yview)
        xs = ttk.Scrollbar(center_pane, orient = 'horizontal', command = self.text_box.xview)
        self.text_box['yscrollcommand'] = ys.set
        self.text_box['xscrollcommand'] = xs.set
        self.text_box.tag_configure('highlightline', background='yellow', font='TkFixedFont', relief='raised')
        self.text_box.grid(column = 0, row = 0, sticky = 'nwes')
        self.text_box["state"] = "disabled"
        xs.grid(column = 0, row = 1, sticky = 'we')
        ys.grid(column = 1, row = 0, sticky = 'ns')
        center_pane.grid_columnconfigure(0, weight = 1)
        center_pane.grid_rowconfigure(0, weight = 1)

        bottom_pane = ttk.Frame(self.root, padding=(5, 0, 5, 0))
        bottom_pane.columnconfigure(1, weight=1)
        self.lb_message = ttk.Label(bottom_pane, text="Your message:")
        self.lb_message.grid(row=0, column=0, padx=10, pady=2, sticky=tk.E)
        self.tf_message = ttk.Entry(bottom_pane, textvariable=self.message)
        self.tf_message.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        self.bt_send = ttk.Button(bottom_pane, text="Send Message", command=self.send_message)
        self.bt_send.grid(row=0, column=2, padx=10, pady=2,sticky=tk.EW)     
        self.bt_follow = ttk.Button(bottom_pane, text="Follow", command=self.follow)
        self.bt_follow.grid(row=0, column=3, padx=10, pady=2,sticky=tk.E)     
        bottom_pane.pack(fill=tk.X)

    def draw_footer_pane(self):
        footer_pane = ttk.Frame(self.root, padding=(5,10,5,0))
        footer_pane.pack(fill=tk.X)
        footer_pane.columnconfigure(1, weight=1)
        self.bt_about = ttk.Button(footer_pane, text="About", command=self.about)
        self.bt_about.grid(row=0, column=0, pady=3, sticky=tk.E)
        self.bt_quit = ttk.Button(footer_pane, text="Quit", command=self.quit)
        self.bt_quit.grid(row=0, column=1, pady=3, sticky=tk.E)

    def not_connected_mode(self):
        self.tf_message.state(["disabled"])
        self.bt_send.state(["disabled"])
        self.bt_follow.state(["disabled"])
    
    def connected_mode(self):
        self.tf_host.state(["disabled"])
        self.tf_port.state(["disabled"])
        self.tf_login.state(["disabled"])
        self.tf_password.state(["disabled"])
        self.bt_register.state(["disabled"])
        self.bt_connect.state(["disabled"])
        self.cb_tls.state(["disabled"])
        self.tf_message.state(["!disabled"])
        self.bt_send.state(["!disabled"])
        self.bt_follow.state(["!disabled"])

    def quit(self):
        self.root.destroy()
        self.controller.on_quit()
    
    def about(self):
        pass

    def follow(self):
        following = self.message.get()
        if following == None or len(following.strip()) == 0:
            self.show_message("Mention user of tag to follow", True)
        else:
            self.controller.on_follow(following)
            self.message.set("")

    def send_message(self):
        message = self.message.get()
        if message == None or len(message.strip()) == 0:
            self.show_message("Message is missing", True)
        else:
            self.controller.on_send(message)
            self.message.set("")

    def no_action(self):
        pass

    def add_message(self, message, is_colored):
        self.text_box["state"] = "normal"
        if is_colored == True:
            self.text_box.insert('end', f"{message}\n", 'highlightline')
        else:
            self.text_box.insert('end', f"{message}\n")
        self.text_box.see("end")
        self.text_box["state"] = "disabled"
    
    def show_message(self, message, is_error):
        if is_error:
            messagebox.showerror("Error", message)
        else:
            messagebox.showinfo("Information", message)
    
    def connect(self):
        if self.check_before_connect():
            print("[MainWindow] Calling MainWindowController::on_connect()")
            self.controller.on_connect(self.host.get(), int(self.port.get()), self.login.get(), self.passw.get(), self.tls.get())
        else:
            self.show_message("All fields are mandatory!\nPort is numeric (1025-65535)", True)

    def register(self):
        if self.check_before_connect():
            print("[MainWindow] Calling MainWindowController::on_register()")
            self.controller.on_register(self.host.get(), int(self.port.get()), self.login.get(), self.passw.get(), self.tls.get())
        else:
            self.show_message("All fields are mandatory!\nPort is numeric (1025-65535)", True)

    def check_before_connect(self):
        try:
            host = self.host.get()
            port = int(self.port.get())
            login = self.login.get()
            passw = self.passw.get()
            tls = self.tls.get()
            if(not(host and host.strip())) or port <= 1024 or port >= 65536 or not (login and login.strip()) or not(passw and passw.strip()):
                return False
            else:
                return True
        except ValueError:
            return False