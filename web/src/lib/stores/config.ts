import { writable } from 'svelte/store';
import { api } from '#lib/api/client.js';

export type AuthMode = 'magic_link' | 'oidc';

export const smsEnabled = writable(false);
export const authMode = writable<AuthMode>('magic_link');
export const oidcName = writable('');

let loaded = false;

export async function loadAppConfig() {
	if (loaded) return;
	try {
		const result = await api.get<{
			data: { smsEnabled: boolean; authMode?: AuthMode; oidcName?: string };
		}>('/config');
		smsEnabled.set(result.data.smsEnabled);
		authMode.set(result.data.authMode === 'oidc' ? 'oidc' : 'magic_link');
		oidcName.set(result.data.oidcName || '');
		loaded = true;
	} catch {
		smsEnabled.set(false);
	}
}
