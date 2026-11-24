import OpenAI from 'openai';
import { Resend } from 'resend';
import Stripe from 'stripe';

export const openai = new OpenAI();
export const resend = new Resend(process.env.RESEND_API_KEY);
export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
