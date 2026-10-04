<template>
  <v-container class="narrow-container">
    <BasePageTitle divider>
      <template #title>
        {{ $t('profile.connected-apps') }}
      </template>
    </BasePageTitle>
    <p>{{ $t('profile.connected-apps-intro') }}</p>
    <v-alert v-if="error" type="error">
      {{ error }}
    </v-alert>
    <v-card v-for="connection in connections" :key="connection.id" class="mb-3">
      <v-card-title>{{ connection.client_name }}</v-card-title>
      <v-card-text>
        <div>{{ connection.client_id }}</div>
        <div>{{ $t('profile.connected-apps-permissions') }}: {{ connection.scopes.join(", ") }}</div>
        <div v-if="connection.revoked">
          {{ $t('profile.connected-apps-revoked') }}
        </div>
      </v-card-text>
      <v-card-actions v-if="!connection.revoked">
        <v-spacer />
        <v-btn color="error" variant="text" @click="revoke(connection.id)">
          {{ $t('profile.connected-apps-revoke') }}
        </v-btn>
      </v-card-actions>
    </v-card>
    <v-alert v-if="!connections.length && !error" type="info">
      {{ $t('profile.connected-apps-empty') }}
    </v-alert>
  </v-container>
</template>

<script setup lang="ts">
definePageMeta({ middleware: ["auth"] });

interface Connection {
  id: number;
  client_name: string;
  client_id: string;
  scopes: string[];
  revoked: boolean;
}

const { $axios } = useNuxtApp();
const i18n = useI18n();
const connections = ref<Connection[]>([]);
const error = ref("");

useSeoMeta({ title: i18n.t("profile.connected-apps") });

async function load() {
  try {
    const response = await $axios.get<Connection[]>("/api/users/mcp/connections");
    connections.value = response.data;
  }
  catch {
    error.value = i18n.t("profile.connected-apps-load-error");
  }
}

async function revoke(id: number) {
  try {
    await $axios.delete(`/api/users/mcp/connections/${id}`);
    await load();
  }
  catch {
    error.value = i18n.t("profile.connected-apps-revoke-error");
  }
}

onMounted(load);
</script>
