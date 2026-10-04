import argparse
import json
import tkinter as tk

from .app import Workbench


def main():
    parser = argparse.ArgumentParser(description='Unveil desktop patch workbench')
    source = parser.add_mutually_exclusive_group()
    source.add_argument('--sample')
    source.add_argument('--project')
    parser.add_argument('--smoke-test', action='store_true', help='Construct widgets and exit without starting targets')
    args = parser.parse_args()
    root = tk.Tk()
    app = Workbench(root)
    if args.smoke_test:
        root.update_idletasks()
        print(json.dumps({'initialized': True, 'tabs': len(app.tabs.tabs()), 'targetExecuted': False,
                          'width': root.winfo_width(), 'height': root.winfo_height()}))
        app.close()
        return 0
    if args.sample:
        app.load_sample(args.sample)
    elif args.project:
        app.load_project(args.project)
    root.mainloop()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
