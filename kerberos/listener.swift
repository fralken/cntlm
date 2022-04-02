#!/usr/bin/swift 
import Foundation 
import AppKit 

var running = ""

class NotifyHandler { 
    var notification: String 
    var action: String 

    init(notification: String, action: String) { 
        self.notification = notification 
        self.action = action 
    } 

    func observe() { 
        DistributedNotificationCenter.default.addObserver( 
            forName: Notification.Name(notification), 
            object: nil, 
            queue: nil, 
            using: self.gotNotification(notification:) 
        ) 
    } 

    func gotNotification(notification: Notification) {
        if running != self.action {
            running = self.action
            runShell(command: self.action)
        } 
    } 
} 

func runShell(command: String) {
    let task = Process() 
    task.launchPath = "/bin/zsh" 
    task.arguments = ["-c", command] 
    task.launch() 
}

let app = NSApplication.shared

class AppDelegate: NSObject, NSApplicationDelegate { 

    func applicationDidFinishLaunching(_ notification: Notification) { 
        let scriptPath: String = CommandLine.arguments.first! 
        var events = [[String]](repeating: [], count: 3)
        var current = -1
        for arg in CommandLine.arguments.dropFirst() {
            switch arg {
                case "-start":
                    current = 2
                case "-notifications":
                    current = 0
                case "-actions":
                    current = 1
                default:
                    if current == -1 {
                        print("\(scriptPath): missing argument type for \"\(arg)\"")
                        exit(1)
                    } 
                    events[current].append(arg)
            } 
        }

        if !events[2].isEmpty {
            for action in events[2] {
                runShell(command: action)
            }
        }

        if events[0].count != events[1].count {
            print("\(scriptPath): notifications are \(events[0].count) but actions are \(events[1].count)")
            exit(1)
        }

        if events[0].isEmpty {
            print("\(scriptPath): no notifications to observe")
            exit(1)
        }

        for (notification, action) in zip(events[0], events[1]) {
            let nh = NotifyHandler.init(notification: notification, action: action)
            nh.observe()
        }
    } 
} 

let delegate = AppDelegate() 
app.delegate = delegate 
app.run()
