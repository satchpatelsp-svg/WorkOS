import { ReactNode } from "react";
import { Link, useLocation } from "wouter";
import { 
  Home, 
  Inbox, 
  Sparkles, 
  Users, 
  Briefcase, 
  Calendar, 
  FileText, 
  CheckSquare, 
  Maximize, 
  BarChart3, 
  Settings 
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

const NAV_ITEMS = [
  { icon: Home, label: "Home", href: "/" },
  { icon: Inbox, label: "Inbox", href: "/inbox", gated: true },
  { icon: Sparkles, label: "Assistant", href: "/assistant", gated: true },
  { icon: Users, label: "Clients", href: "/clients", gated: true },
  { icon: Briefcase, label: "Deals", href: "/deals", gated: true },
  { icon: Calendar, label: "Calendar", href: "/calendar", gated: true },
  { icon: FileText, label: "Documents", href: "/documents", gated: true },
  { icon: CheckSquare, label: "Tasks", href: "/tasks", gated: true },
  { icon: Maximize, label: "Cockpit", href: "/cockpit", gated: true },
  { icon: BarChart3, label: "Reports", href: "/reports", gated: true },
];

export function Sidebar() {
  const [location] = useLocation();

  return (
    <aside className="w-56 h-screen border-r border-sidebar-border bg-sidebar flex flex-col pt-4 pb-4 select-none shrink-0 sticky top-0">
      <div className="px-5 mb-6 flex items-center gap-2 text-foreground font-semibold">
        <Sparkles className="w-4 h-4 text-primary" />
        WORK OS
      </div>

      <nav className="flex-1 px-3 space-y-0.5">
        {NAV_ITEMS.map((item) => {
          const isActive = location === item.href;
          
          const content = (
            <div
              className={cn(
                "flex items-center gap-3 px-2 py-1.5 rounded-md text-[13px] font-medium transition-colors cursor-pointer",
                isActive
                  ? "bg-accent/50 text-foreground"
                  : "text-muted-foreground hover:bg-accent/30 hover:text-foreground",
                item.gated && "opacity-70"
              )}
            >
              <item.icon className="w-[15px] h-[15px]" strokeWidth={2.5} />
              {item.label}
            </div>
          );

          if (item.gated) {
            return (
              <Tooltip key={item.label} delayDuration={100}>
                <TooltipTrigger asChild>
                  <div>{content}</div>
                </TooltipTrigger>
                <TooltipContent side="right" className="font-mono text-[10px]">
                  Gated (Stage A)
                </TooltipContent>
              </Tooltip>
            );
          }

          return (
            <Link key={item.label} href={item.href}>
              {content}
            </Link>
          );
        })}
      </nav>

      <div className="px-3 mt-auto">
        <Tooltip delayDuration={100}>
          <TooltipTrigger asChild>
            <div className="flex items-center gap-3 px-2 py-1.5 rounded-md text-[13px] font-medium text-muted-foreground hover:bg-accent/30 hover:text-foreground cursor-pointer opacity-70">
              <Settings className="w-[15px] h-[15px]" strokeWidth={2.5} />
              Settings
            </div>
          </TooltipTrigger>
          <TooltipContent side="right" className="font-mono text-[10px]">
            Gated (Stage A)
          </TooltipContent>
        </Tooltip>
      </div>

      <div className="px-5 mt-4 pt-4 border-t border-sidebar-border flex items-center gap-3">
        <div className="w-7 h-7 rounded-full bg-accent/80 flex items-center justify-center text-[10px] font-bold text-accent-foreground border border-sidebar-border">
          EW
        </div>
        <div className="flex flex-col">
          <span className="text-[12px] font-semibold text-foreground leading-tight">Emily Watson</span>
          <span className="text-[10px] text-muted-foreground leading-tight">EA Operator</span>
        </div>
      </div>
    </aside>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-[100dvh] w-full bg-background text-foreground">
      <Sidebar />
      <main className="flex-1 flex flex-col min-w-0">
        {children}
      </main>
    </div>
  );
}
