import { Search, Bell, ChevronDown } from "lucide-react";
import { useHealthCheck } from "@workspace/api-client-react";
import { cn } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

export function Header() {
  const { data: health, isLoading } = useHealthCheck();

  return (
    <header className="h-14 border-b border-border flex items-center justify-between px-6 shrink-0 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60 sticky top-0 z-10">
      <div className="flex items-center w-full max-w-lg">
        <Tooltip delayDuration={100}>
          <TooltipTrigger asChild>
            <div className="relative w-full opacity-60">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input 
                type="search"
                placeholder="Search clients, deals, tasks, documents..."
                className="w-full h-8 pl-9 pr-4 rounded-md bg-input/40 border border-input text-[13px] placeholder:text-muted-foreground focus:outline-none transition-shadow cursor-not-allowed pointer-events-none"
                disabled
              />
            </div>
          </TooltipTrigger>
          <TooltipContent side="bottom" className="font-mono text-[10px]">
            Gated (Stage A)
          </TooltipContent>
        </Tooltip>
      </div>
      
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <div className={cn(
            "w-2 h-2 rounded-full",
            isLoading ? "bg-muted-foreground animate-pulse" : (health?.status === "ok" ? "bg-[hsl(160,50%,45%)]" : "bg-destructive")
          )} />
          <span className="text-[11px] font-mono text-muted-foreground uppercase tracking-wider">
            {isLoading ? "Checking..." : (health?.status === "ok" ? "System Ready" : "System Degraded")}
          </span>
        </div>

        <Tooltip delayDuration={100}>
          <TooltipTrigger asChild>
            <button className="relative w-8 h-8 flex items-center justify-center rounded-md hover:bg-accent/50 text-muted-foreground hover:text-foreground transition-colors opacity-70">
              <Bell className="w-[15px] h-[15px]" strokeWidth={2} />
              <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 bg-destructive rounded-full" />
            </button>
          </TooltipTrigger>
          <TooltipContent side="bottom" className="font-mono text-[10px]">
            Gated (Stage A)
          </TooltipContent>
        </Tooltip>
        
        <Tooltip delayDuration={100}>
          <TooltipTrigger asChild>
            <div className="flex items-center gap-2 cursor-not-allowed opacity-70 hover:opacity-100 transition-opacity">
              <div className="w-7 h-7 rounded-full bg-secondary flex items-center justify-center text-[10px] font-bold text-secondary-foreground">
                EW
              </div>
              <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />
            </div>
          </TooltipTrigger>
          <TooltipContent side="bottom" className="font-mono text-[10px]">
            Identity Gated
          </TooltipContent>
        </Tooltip>
      </div>
    </header>
  );
}
