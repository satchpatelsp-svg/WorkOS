import { AlertCircle } from "lucide-react";

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[50vh] text-center px-4">
      <AlertCircle className="w-12 h-12 text-muted-foreground mb-4" strokeWidth={1.5} />
      <h1 className="text-xl font-bold text-foreground mb-2">Page Not Found</h1>
      <p className="text-[13px] text-muted-foreground max-w-md mx-auto">
        The requested surface does not exist or is gated behind Stage B access controls. Please return to the foundation shell.
      </p>
    </div>
  );
}
