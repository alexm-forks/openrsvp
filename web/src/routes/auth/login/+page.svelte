<script lang="ts">
	import { api } from '#lib/api/client.js';
	import { toast } from '#lib/stores/toast.js';
	import { isValidEmail } from '#lib/utils/validation.js';
	import Button from '#lib/components/ui/Button.svelte';
	import Input from '#lib/components/ui/Input.svelte';
	import Spinner from '#lib/components/ui/Spinner.svelte';
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { authMode, oidcName, loadAppConfig } from '#lib/stores/config.js';

	// Messages for the error codes the OIDC callback sends back. Unknown
	// codes fall back to the generic message; the text is never taken from
	// the URL.
	const oidcErrors: Record<string, string> = {
		unavailable: 'The sign-in service is unavailable right now. Please try again shortly.',
		denied: 'Sign-in was cancelled.',
		state: 'Your sign-in session expired. Please try again.',
		unverified_email:
			'Your account needs a verified email address. Verify it with your identity provider, then try again.',
		not_allowed: 'Your account is not allowed to use this OpenRSVP instance.',
		email_conflict:
			'Your email address is already linked to a different account. Ask an administrator for help.',
		failed: 'Sign-in failed. Please try again.'
	};

	let configReady = $state(false);
	const errorCode = $derived(page.url.searchParams.get('error'));
	const oidcError = $derived(errorCode ? (oidcErrors[errorCode] ?? oidcErrors.failed) : '');

	onMount(async () => {
		await loadAppConfig();
		configReady = true;
	});

	let email = $state('');
	let loading = $state(false);
	let sent = $state(false);
	let emailError = $state('');

	async function handleSubmit(e: SubmitEvent) {
		e.preventDefault();
		emailError = '';

		if (!email.trim()) {
			emailError = 'Email is required';
			return;
		}

		if (!isValidEmail(email)) {
			emailError = 'Please enter a valid email address';
			return;
		}

		loading = true;
		try {
			await api.post('/auth/magic-link', { email });
			sent = true;
		} catch (err: unknown) {
			const apiErr = err as { message?: string };
			toast.error(apiErr.message || 'Failed to send magic link. Please try again.');
		} finally {
			loading = false;
		}
	}
</script>

<svelte:head>
	<title>Sign In -- OpenRSVP</title>
</svelte:head>

<div class="min-h-screen flex items-center justify-center px-4">
	<div class="w-full max-w-md">
		<div class="text-center mb-8">
			<a href="/" class="text-2xl font-bold text-primary">OpenRSVP</a>
			<h1 class="font-display mt-4 text-2xl font-semibold text-neutral-900">Sign in to your account</h1>
			{#if configReady && $authMode === 'oidc'}
				<p class="mt-2 text-neutral-600">Sign in with your {$oidcName || 'SSO'} account</p>
			{:else if configReady}
				<p class="mt-2 text-neutral-600">Enter your email to receive a magic link</p>
			{/if}
		</div>

		<div class="bg-surface rounded-lg shadow-sm border border-neutral-200 p-8">
			{#if !configReady}
				<div class="flex justify-center py-4"><Spinner /></div>
			{:else if $authMode === 'oidc'}
				{#if oidcError}
					<p
						class="mb-6 rounded-md border border-error/30 bg-error-light px-4 py-3 text-sm text-error"
						role="alert"
					>
						{oidcError}
					</p>
				{/if}
				<!-- Full page navigation: the server redirects to the identity provider. -->
				<a
					href="/api/v1/auth/oidc/login"
					data-sveltekit-reload
					class="inline-flex w-full items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-white transition-colors duration-short ease-out hover:bg-primary-hover focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2"
				>
					Sign in with {$oidcName || 'SSO'}
				</a>

				<div class="mt-6 text-center">
					<a href="/" class="text-sm text-primary hover:text-primary-hover">
						Back to home
					</a>
				</div>
			{:else if sent}
				<!-- Success state -->
				<div class="text-center">
					<div
						class="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-success-light mb-4"
					>
						<svg
							class="h-6 w-6 text-success"
							fill="none"
							viewBox="0 0 24 24"
							stroke="currentColor"
						>
							<path
								stroke-linecap="round"
								stroke-linejoin="round"
								stroke-width="2"
								d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
							/>
						</svg>
					</div>
					<h2 class="text-lg font-semibold text-neutral-900 mb-2">Check your email</h2>
					<p class="text-sm text-neutral-600 mb-4">
						We sent a magic link to <strong>{email}</strong>. Click the link in the email to sign
						in.
					</p>
					<p class="text-xs text-neutral-500 mb-6">
						Did not receive the email? Check your spam folder or try again.
					</p>
					<Button
						variant="outline"
						onclick={() => {
							sent = false;
							email = '';
						}}
					>
						Try a different email
					</Button>
				</div>
			{:else}
				<!-- Login form -->
				<form onsubmit={handleSubmit} class="space-y-6">
					<Input
						label="Email address"
						name="email"
						type="email"
						bind:value={email}
						placeholder="you@example.com"
						error={emailError}
						required
					/>

					<Button type="submit" {loading} class="w-full">
						{loading ? 'Sending...' : 'Send Magic Link'}
					</Button>
				</form>

				<div class="mt-6 text-center">
					<a href="/" class="text-sm text-primary hover:text-primary-hover">
						Back to home
					</a>
				</div>
			{/if}
		</div>
	</div>
</div>
