import { useState } from 'react';
import { useAuth } from '@/context/AuthContext';
import { Shield, Mail, Lock, Chrome, Eye, EyeOff, User } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { useToast } from '@/hooks/use-toast';

type Mode = 'login' | 'signup' | 'reset';

export default function LoginPage() {
    const { signIn, signUp, signInWithGoogle, resetPassword } = useAuth();
    const { toast } = useToast();

    const [mode, setMode] = useState<Mode>('login');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [displayName, setDisplayName] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        try {
            if (mode === 'login') {
                await signIn(email, password);
                toast({ title: 'Welcome back!', description: 'Signed in successfully.' });
            } else if (mode === 'signup') {
                await signUp(email, password, displayName);
                toast({ title: 'Account created!', description: 'Welcome to Metadata Forensic Suite.' });
            } else {
                await resetPassword(email);
                toast({ title: 'Reset email sent', description: 'Check your inbox for a reset link.' });
                setMode('login');
            }
        } catch (err: any) {
            const msg = err?.message?.replace('Firebase: ', '').replace(/\(auth\/.*\)\.?/, '').trim();
            toast({ title: 'Error', description: msg || 'Something went wrong.', variant: 'destructive' });
        } finally {
            setLoading(false);
        }
    };

    const handleGoogle = async () => {
        setLoading(true);
        try {
            await signInWithGoogle();
            toast({ title: 'Welcome!', description: 'Signed in with Google.' });
        } catch (err: any) {
            toast({ title: 'Google sign-in failed', description: err?.message, variant: 'destructive' });
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-background p-4">
            {/* Background grid effect */}
            <div className="absolute inset-0 bg-[linear-gradient(to_right,hsl(220,30%,10%)_1px,transparent_1px),linear-gradient(to_bottom,hsl(220,30%,10%)_1px,transparent_1px)] bg-[size:40px_40px] opacity-30 pointer-events-none" />

            <Card className="w-full max-w-md relative border border-border/50 bg-card/80 backdrop-blur-sm shadow-2xl">
                <CardHeader className="text-center pb-2 pt-8">
                    {/* Logo */}
                    <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-primary/10 border border-primary/20">
                        <Shield className="h-8 w-8 text-primary" />
                    </div>
                    <h1 className="text-2xl font-bold text-foreground">Metadata Forensic Suite</h1>
                    <p className="text-sm text-muted-foreground mt-1">
                        {mode === 'login' && 'Sign in to your investigator account'}
                        {mode === 'signup' && 'Create an investigator account'}
                        {mode === 'reset' && 'Reset your password'}
                    </p>
                </CardHeader>

                <CardContent className="p-6 space-y-4">
                    <form onSubmit={handleSubmit} className="space-y-3">
                        {/* Name field for signup */}
                        {mode === 'signup' && (
                            <div className="relative">
                                <User className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                                <Input
                                    id="displayName"
                                    type="text"
                                    placeholder="Full name"
                                    value={displayName}
                                    onChange={(e) => setDisplayName(e.target.value)}
                                    className="pl-10"
                                    required
                                />
                            </div>
                        )}

                        {/* Email */}
                        <div className="relative">
                            <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                            <Input
                                id="email"
                                type="email"
                                placeholder="Email address"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                className="pl-10"
                                required
                                autoComplete="email"
                            />
                        </div>

                        {/* Password */}
                        {mode !== 'reset' && (
                            <div className="relative">
                                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                                <Input
                                    id="password"
                                    type={showPassword ? 'text' : 'password'}
                                    placeholder="Password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    className="pl-10 pr-10"
                                    required
                                    minLength={6}
                                    autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowPassword(!showPassword)}
                                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                                    tabIndex={-1}
                                >
                                    {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                                </button>
                            </div>
                        )}

                        {/* Forgot password link */}
                        {mode === 'login' && (
                            <div className="flex justify-end">
                                <button
                                    type="button"
                                    onClick={() => setMode('reset')}
                                    className="text-xs text-primary hover:underline"
                                >
                                    Forgot password?
                                </button>
                            </div>
                        )}

                        <Button type="submit" className="w-full" disabled={loading}>
                            {loading
                                ? 'Please wait...'
                                : mode === 'login'
                                    ? 'Sign In'
                                    : mode === 'signup'
                                        ? 'Create Account'
                                        : 'Send Reset Email'}
                        </Button>
                    </form>

                    {/* Divider */}
                    {mode !== 'reset' && (
                        <>
                            <div className="relative">
                                <div className="absolute inset-0 flex items-center">
                                    <span className="w-full border-t border-border" />
                                </div>
                                <div className="relative flex justify-center text-xs">
                                    <span className="bg-card px-2 text-muted-foreground">or continue with</span>
                                </div>
                            </div>

                            {/* Google Sign-In */}
                            <Button
                                id="google-signin-btn"
                                type="button"
                                variant="outline"
                                className="w-full gap-2"
                                onClick={handleGoogle}
                                disabled={loading}
                            >
                                <Chrome className="h-4 w-4" />
                                Google
                            </Button>
                        </>
                    )}

                    {/* Mode switcher */}
                    <p className="text-center text-sm text-muted-foreground pt-2">
                        {mode === 'login' ? (
                            <>
                                Don&apos;t have an account?{' '}
                                <button onClick={() => setMode('signup')} className="text-primary hover:underline font-medium">
                                    Sign up
                                </button>
                            </>
                        ) : (
                            <>
                                Already have an account?{' '}
                                <button onClick={() => setMode('login')} className="text-primary hover:underline font-medium">
                                    Sign in
                                </button>
                            </>
                        )}
                    </p>
                </CardContent>
            </Card>
        </div>
    );
}
