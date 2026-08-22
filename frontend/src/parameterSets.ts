/** Parameter-set persistence shared by both editors. */
import { api, ApiError } from './api';
import { freshIdentifier } from './drafts';
import type { ParameterSet } from './types';

export async function saveParameterSet(
  value: ParameterSet,
  options: { replace: boolean; regenerateIdOnConflict: boolean },
): Promise<ParameterSet> {
  let candidate = value;
  for (let attempt = 0; ; attempt += 1) {
    try {
      await api(`/v1/parameter-sets/import?conflict=${options.replace ? 'replace' : 'reject'}`, {
        method: 'POST',
        body: JSON.stringify(candidate),
      });
      return candidate;
    } catch (error) {
      if (
        options.regenerateIdOnConflict
        && error instanceof ApiError
        && error.status === 409
        && attempt < 4
      ) {
        candidate = { ...candidate, id: freshIdentifier('scheme') };
        continue;
      }
      throw error;
    }
  }
}
