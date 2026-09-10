import { useGetFoundationSummary } from "@workspace/api-client-react";
import { 
  CheckCircle2, 
  Clock, 
  CircleAlert, 
  FileText, 
  MessageSquare,
  ShieldCheck,
  ShieldAlert,
  Calendar as CalendarIcon,
  ChevronRight
} from "lucide-react";
import { format, parseISO } from "date-fns";
import { cn } from "@/lib/utils";

function StatCard({ icon: Icon, value, label, colorClass }: { icon: any, value: string | number, label: string, colorClass: string }) {
  return (
    <div className="flex flex-col gap-1 p-3 rounded-lg border border-border bg-card shadow-xs">
      <div className="flex items-center justify-between">
        <Icon className={cn("w-4 h-4", colorClass)} strokeWidth={2.5} />
        <span className="text-[16px] font-semibold text-foreground tracking-tight">{value}</span>
      </div>
      <span className="text-[11px] text-muted-foreground font-medium mt-1">{label}</span>
    </div>
  );
}

function SectionHeader({ title, action }: { title: string, action?: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between mb-3">
      <h2 className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">{title}</h2>
      {action && <div className="text-[12px] font-medium text-primary hover:underline cursor-pointer">{action}</div>}
    </div>
  );
}

export function Home() {
  const { data: summary, isLoading, isError } = useGetFoundationSummary();

  if (isLoading) {
    return (
      <div className="p-8 space-y-6 animate-pulse">
        <div className="h-10 w-48 bg-accent/50 rounded-md" />
        <div className="grid grid-cols-5 gap-3">
          {[...Array(5)].map((_, i) => <div key={i} className="h-20 bg-accent/50 rounded-lg" />)}
        </div>
        <div className="grid grid-cols-2 gap-6 mt-8">
          <div className="space-y-3">
            <div className="h-4 w-32 bg-accent/50 rounded" />
            <div className="h-64 bg-accent/50 rounded-lg" />
          </div>
          <div className="space-y-3">
            <div className="h-4 w-32 bg-accent/50 rounded" />
            <div className="h-64 bg-accent/50 rounded-lg" />
          </div>
        </div>
      </div>
    );
  }

  if (isError || !summary) {
    return (
      <div className="p-8 text-destructive">
        Failed to load foundation summary.
      </div>
    );
  }

  const tasksCount = summary.workItems.length;
  const reviewCount = summary.workItems.filter(i => i.status.toLowerCase().includes("review") || i.status.toLowerCase().includes("approval")).length;
  const escalationCount = summary.workItems.filter(i => i.priority.toLowerCase() === "high" || i.priority.toLowerCase() === "urgent").length;

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="max-w-6xl mx-auto p-6 md:p-8 space-y-8">
        
        {/* Welcome Section */}
        <div className="flex items-end justify-between">
          <div>
            <h1 className="text-[22px] font-bold text-foreground tracking-tight mb-1">
              Good morning, Emily
            </h1>
            <p className="text-[13px] text-muted-foreground">
              Here's what needs your attention today.
            </p>
          </div>
          <div className="text-[12px] font-medium text-muted-foreground">
            {format(new Date(), "EEEE, d MMMM yyyy")}
          </div>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-5 gap-3">
          <StatCard icon={CheckCircle2} value={tasksCount} label="Tasks due" colorClass="text-[hsl(30,40%,65%)]" />
          <StatCard icon={FileText} value={reviewCount} label="Awaiting your review" colorClass="text-[hsl(30,50%,55%)]" />
          <StatCard icon={MessageSquare} value={3} label="Client updates" colorClass="text-[hsl(160,50%,45%)]" />
          <StatCard icon={CircleAlert} value={escalationCount} label="Escalations" colorClass="text-destructive" />
          <StatCard icon={CalendarIcon} value={1} label="Today's meetings" colorClass="text-primary" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          
          {/* Priorities */}
          <section>
            <SectionHeader title="Today's Priorities" action="View all tasks" />
            <div className="space-y-1">
              {summary.workItems.slice(0, 5).map((item) => (
                <div key={item.id} className="flex items-start gap-4 p-3 rounded-md hover:bg-accent/30 transition-colors group cursor-pointer border border-transparent hover:border-border">
                  <div className="w-[42px] pt-0.5 text-[11px] font-mono text-muted-foreground font-medium shrink-0">
                    {/* Mock time if not provided, just extracting a bit of variety */}
                    {item.dueLabel.includes("Today") ? "09:00" : "14:30"}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-[13px] font-semibold text-foreground truncate">{item.title}</div>
                    <div className="text-[12px] text-muted-foreground truncate">{item.owner}</div>
                  </div>
                  <div className="shrink-0 flex items-center justify-end min-w-[70px]">
                    <span className={cn(
                      "px-2 py-0.5 rounded text-[10px] font-semibold tracking-wide uppercase",
                      item.status.toLowerCase().includes("review") ? "bg-[hsl(30,40%,90%)] text-[hsl(30,50%,35%)] dark:bg-[hsl(30,40%,20%)] dark:text-[hsl(30,40%,65%)]" :
                      item.status.toLowerCase().includes("approval") ? "bg-[hsl(160,30%,90%)] text-[hsl(160,50%,35%)] dark:bg-[hsl(160,40%,20%)] dark:text-[hsl(160,50%,65%)]" :
                      "bg-primary/10 text-primary dark:bg-primary/20 dark:text-primary"
                    )}>
                      {item.status}
                    </span>
                  </div>
                </div>
              ))}
              {summary.workItems.length === 0 && (
                <div className="p-4 text-center text-[13px] text-muted-foreground border border-dashed border-border rounded-md">
                  No priorities today.
                </div>
              )}
            </div>
          </section>

          {/* Recent Activity */}
          <section>
            <SectionHeader title="Recent Activity" action="View all activity" />
            <div className="space-y-1 relative before:absolute before:inset-y-0 before:left-[17px] before:w-px before:bg-border">
              {summary.recentActivity.slice(0, 5).map((activity) => (
                <div key={activity.id} className="flex items-start gap-3 p-2 relative z-0 group cursor-pointer">
                  <div className="w-5 h-5 rounded-full bg-background border border-border flex items-center justify-center shrink-0 mt-0.5 relative z-10 group-hover:border-primary transition-colors">
                    <div className="w-1.5 h-1.5 rounded-full bg-primary/60 group-hover:bg-primary transition-colors" />
                  </div>
                  <div className="flex-1 min-w-0 pb-2">
                    <div className="flex items-baseline justify-between gap-2">
                      <div className="text-[13px] font-medium text-foreground truncate">{activity.label}</div>
                      <div className="text-[11px] text-muted-foreground whitespace-nowrap">
                        {/* Try parsing ISO, fallback to text */}
                        {activity.occurredAt.includes("T") ? format(parseISO(activity.occurredAt), "HH:mm") : activity.occurredAt}
                      </div>
                    </div>
                    <div className="text-[12px] text-muted-foreground mt-0.5 truncate">{activity.actor}</div>
                  </div>
                </div>
              ))}
            </div>
          </section>

        </div>

        {/* Foundation Info footer row */}
        <section className="mt-8 pt-6 border-t border-border">
          <SectionHeader title="Security & Foundation Readiness (Stage A)" />
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-3">
            <div className="p-4 rounded-lg bg-sidebar border border-sidebar-border">
              <h3 className="text-[12px] font-bold text-foreground mb-1">Context</h3>
              <dl className="space-y-1 text-[12px]">
                <div className="flex justify-between"><dt className="text-muted-foreground">Tenant</dt><dd className="font-mono">{summary.tenant.name}</dd></div>
                <div className="flex justify-between"><dt className="text-muted-foreground">Workspace</dt><dd className="font-mono">{summary.workspace.name}</dd></div>
                <div className="flex justify-between"><dt className="text-muted-foreground">Principal</dt><dd className="font-mono">{summary.principal.name}</dd></div>
                <div className="flex justify-between"><dt className="text-muted-foreground">Mode</dt><dd className="font-mono capitalize">{summary.mode.replace('-', ' ')}</dd></div>
              </dl>
            </div>
            
            <div className="p-4 rounded-lg bg-sidebar border border-sidebar-border col-span-1 md:col-span-2">
              <h3 className="text-[12px] font-bold text-foreground mb-3">Controls</h3>
              <div className="grid grid-cols-2 gap-3">
                {summary.security.map((control) => (
                  <div key={control.name} className="flex items-start gap-2">
                    {control.status === 'ready' ? (
                      <ShieldCheck className="w-4 h-4 text-[hsl(160,50%,45%)] shrink-0 mt-0.5" />
                    ) : (
                      <ShieldAlert className="w-4 h-4 text-[hsl(30,50%,55%)] shrink-0 mt-0.5" />
                    )}
                    <div>
                      <div className="text-[12px] font-semibold text-foreground flex items-center gap-2">
                        {control.name}
                        {control.status !== 'ready' && (
                          <span className="text-[9px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-muted text-muted-foreground">{control.status}</span>
                        )}
                      </div>
                      <div className="text-[11px] text-muted-foreground mt-0.5 leading-snug">{control.detail}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

      </div>
    </div>
  );
}
