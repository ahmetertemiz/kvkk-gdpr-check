import AsyncStorage from '@react-native-async-storage/async-storage';
import posthog from 'posthog-react-native';

export async function onLogin(user, token) {
  await AsyncStorage.setItem('token', token);
  posthog.identify(user.id, { email: user.email });
  fetch(`https://api.example.com/verify?email=${user.email}`);
}
