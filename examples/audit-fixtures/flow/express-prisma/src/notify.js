import Twilio from 'twilio';

const client = Twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);

export async function notifyUser(address, tel) {
  await client.messages.create({ to: tel, from: '+100000', body: 'Welcome!' });
  console.log('notified', address);
}
