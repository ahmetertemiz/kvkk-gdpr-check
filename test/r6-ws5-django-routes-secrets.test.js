// kvkk-ignore-file
/**
 * Round 6 / WS5: Django / DRF projects and settings secrets.
 *  - cross-file Django model inheritance (abstract bases, auth bases, proxy and multi-table models, unresolved bases)
 *  - SQLAlchemy column mixins declared in another module
 *  - DRF routers, generic views, include() prefixes, regex groups, permission classes
 *  - ModelSerializer fields as reads / writes, registration enumeration via unique-field validation
 *  - literal signing secrets and DEBUG / ALLOWED_HOSTS in settings modules
 * All secret values below are synthetic.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildGraph } from '../src/audit/index.js';
import { parseDjangoProject, parseSqlAlchemy, sqlAlchemyMixins } from '../src/audit/extract/orm-python.js';
import { djangoPath } from '../src/audit/extract/routes.js';
import { secretFindings } from '../src/audit/legal/secrets.js';

function tmpRepo(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-r6ws5-'));
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  }
  return dir;
}
const cols = (t) => [...t.columns.keys()].sort();

// A project written in a different style from the benchmark repo: field classes imported by name, aliased imports,
// module-qualified bases, AbstractUser instead of AbstractBaseUser, settings.AUTH_USER_MODEL references.
const MODELS = {
  'proj/settings.py': `INSTALLED_APPS = ['core', 'accounts', 'shop']\nAUTH_USER_MODEL = 'accounts.Member'\n`,
  'core/models.py': `from django.db.models import Model, DateTimeField

class BaseModel(Model):
    created = DateTimeField(auto_now_add=True)

    class Meta:
        abstract = True
        ordering = ['-created']
`,
  'accounts/models.py': `from django.contrib.auth.models import AbstractUser
from django.db import models
from core.models import BaseModel as Base


class Member(AbstractUser, Base):
    phone_number = models.CharField(max_length=20, unique=True)
    birth_date = models.DateField(null=True)

    def __str__(self):
        return self.email
`,
  'shop/models.py': `from django.conf import settings
from django.db import models
from core import models as core_models


class Order(core_models.BaseModel):
    buyer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    shipping_address = models.TextField()


class ArchivedOrder(Order):
    class Meta:
        proxy = True


class Invoice(Order):
    iban = models.CharField(max_length=34)


class Legacy(UnknownBase):
    note = models.CharField(max_length=10)
`,
};

test('Django: abstract base in another app, auth base, proxy and multi-table models resolve across files', () => {
  const files = Object.entries(MODELS).map(([rel, content]) => ({ rel, content }));
  const stats = { unparsed: 0, items: [] };
  const { tables, info } = parseDjangoProject(files, stats);
  assert.deepEqual([...tables.keys()].sort(), ['invoice', 'member', 'order']);
  const member = tables.get('member');
  assert.equal(member.name, 'accounts_member');
  assert.equal(member.model, 'Member');
  // AbstractUser's documented fields + the abstract base's field + own fields (first_name is not referenced: left out).
  for (const c of ['password', 'username', 'email', 'created', 'phone_number', 'birth_date']) assert.ok(member.columns.has(c), c);
  assert.ok(!member.columns.has('first_name'));
  const order = tables.get('order');
  assert.deepEqual(cols(order), ['buyer_id', 'created', 'shipping_address']);
  assert.equal(order.fks[0].refTable, 'member'); // settings.AUTH_USER_MODEL → accounts.Member
  assert.deepEqual(order.extra?.proxies, ['ArchivedOrder']);
  const invoice = tables.get('invoice');
  assert.ok(invoice.columns.has('order_ptr_id') && invoice.columns.has('iban'));
  assert.equal(invoice.fks.find((f) => f.column === 'order_ptr_id').refTable, 'order');
  assert.ok(info.Member.user);
  assert.ok(info.Member.unique.includes('username') && info.Member.unique.includes('phone_number'));
  // A class with model fields whose base cannot be resolved is partial coverage, not silence.
  assert.equal(stats.unparsed, 1);
  assert.equal(stats.items[0].name, 'Legacy');
});

test('Django: buildGraph yields personal data, coverage list (C2) and no abstract table', async () => {
  const { graph, ctx } = await buildGraph(tmpRepo(MODELS));
  assert.ok(graph.has('store:table:member'));
  assert.ok(!graph.has('store:table:basemodel'));
  assert.deepEqual(graph.out('store:column:member.email', 'represents').map((n) => n.id), ['data:email']);
  assert.ok(graph.out('store:column:invoice.iban', 'represents').some((n) => n.id === 'data:iban'));
  assert.ok(Array.isArray(ctx.shared.unparsed) && ctx.shared.unparsed.some((u) => u.name === 'Legacy'));
  assert.equal(ctx.shared.pythonModelsUnparsed, 1);
});

test('SQLAlchemy: column mixin declared in another module is inherited; declared_attr columns are read', () => {
  const mixinFile = { rel: 'app/mixins.py', content: `from sqlalchemy import Column, DateTime, String
from sqlalchemy.orm import declared_attr

class AuditMixin:
    created_at = Column(DateTime)

    @declared_attr
    def created_by_email(cls):
        return Column(String(255))
` };
  const modelFile = { rel: 'app/models.py', content: `from app.db import Base
from app.mixins import AuditMixin
from sqlalchemy import Column, Integer, String

class Patient(AuditMixin, Base):
    __tablename__ = 'patients'
    id = Column(Integer, primary_key=True)
    full_name = Column(String(100))
` };
  const mixins = sqlAlchemyMixins([mixinFile, modelFile]);
  assert.ok(mixins.has('AuditMixin'));
  const t = parseSqlAlchemy(modelFile, { unparsed: 0 }, { mixins });
  assert.deepEqual(cols(t.get('patients')), ['created_at', 'created_by_email', 'full_name', 'id']);
});

test('djangoPath: regex groups become :params, anchors and optional slashes go away', () => {
  assert.equal(djangoPath('^articles/(?P<article_slug>[-\\w]+)/comments/(?P<comment_pk>[\\d]+)/?$', true), 'articles/:article_slug/comments/:comment_pk/');
  assert.equal(djangoPath('^files/(?P<kind>(?:img|doc))/(\\d+)$', true), 'files/:kind/:param');
  assert.equal(djangoPath('users/<int:pk>/', false), 'users/:pk/');
});

const API = {
  'proj/settings.py': `INSTALLED_APPS = ['rest_framework', 'accounts', 'shop']
ROOT_URLCONF = 'proj.urls'
AUTH_USER_MODEL = 'accounts.Member'
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': ['rest_framework.permissions.IsAuthenticated'],
}
`,
  'proj/urls.py': `"""Routes.

Example: url(r'^$', views.home, name='home')
"""
from django.urls import include, path

urlpatterns = [
    path('api/v1/', include('shop.urls')),
    path('api/v1/', include('accounts.urls')),
]
`,
  'accounts/models.py': `from django.contrib.auth.models import AbstractUser
from django.db import models

class Member(AbstractUser):
    email = models.EmailField(unique=True)
    bio = models.TextField(blank=True)
`,
  'accounts/serializers.py': `from django.contrib.auth import get_user_model
from rest_framework import serializers


class SignupSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ('email', 'password', 'bio')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        return get_user_model().objects.create_user(**validated_data)


class InviteSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()

    class Meta:
        model = get_user_model()
        fields = ('email',)
`,
  'accounts/views.py': `from rest_framework import generics, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from .serializers import SignupSerializer, InviteSerializer


class SignupView(generics.CreateAPIView):
    serializer_class = SignupSerializer
    permission_classes = [permissions.AllowAny]


class MemberDetail(generics.RetrieveUpdateAPIView):
    serializer_class = SignupSerializer

    def get_object(self):
        return self.request.user


@api_view(['POST'])
@permission_classes([AllowAny])
def invite(request):
    s = InviteSerializer(data=request.data)
    s.is_valid(raise_exception=True)
    return Response({})
`,
  'accounts/urls.py': `from django.urls import path, re_path
from . import views

urlpatterns = [
    path('signup/', views.SignupView.as_view()),
    re_path(r'^members/(?P<member_id>[0-9]+)/$', views.MemberDetail.as_view()),
    path('invite/', views.invite),
]
`,
  'shop/models.py': `from django.conf import settings
from django.db import models

class Order(models.Model):
    buyer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    note = models.TextField()
`,
  'shop/views.py': `from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from .models import Order


class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()
    permission_classes = (IsAuthenticatedOrReadOnly,)

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        return None
`,
  'shop/urls.py': `from rest_framework import routers
from .views import OrderViewSet

router = routers.SimpleRouter()
router.register(r'orders', OrderViewSet, basename='order')

urlpatterns = router.urls
`,
};

test('DRF: router viewsets, generic view methods, include() prefixes, regex groups and permission classes', async () => {
  const { graph } = await buildGraph(tmpRepo(API));
  const eps = new Map(graph.nodesOf('Endpoint').filter((e) => e.framework === 'django').map((e) => [`${e.method} ${e.path}`, e]));
  for (const k of ['GET /api/v1/orders', 'POST /api/v1/orders', 'GET /api/v1/orders/:pk', 'PUT /api/v1/orders/:pk', 'PATCH /api/v1/orders/:pk', 'DELETE /api/v1/orders/:pk', 'POST /api/v1/orders/:pk/cancel']) assert.ok(eps.has(k), k);
  assert.equal(eps.get('GET /api/v1/orders').auth, false); // IsAuthenticatedOrReadOnly: reads are public
  assert.equal(eps.get('POST /api/v1/orders').auth, true);
  // RetrieveUpdateAPIView answers GET / PUT / PATCH (not POST); no permission_classes → DEFAULT_PERMISSION_CLASSES.
  assert.ok(eps.has('GET /api/v1/members/:member_id') && eps.has('PUT /api/v1/members/:member_id') && eps.has('PATCH /api/v1/members/:member_id'));
  assert.ok(!eps.has('POST /api/v1/members/:member_id'));
  assert.equal(eps.get('PATCH /api/v1/members/:member_id').auth, true);
  assert.equal(eps.get('POST /api/v1/signup').auth, false);
  assert.equal(eps.get('POST /api/v1/invite').auth, false); // @api_view(['POST']) + @permission_classes([AllowAny])
  // The docstring example in proj/urls.py is not a route.
  assert.ok(![...eps.keys()].some((k) => / \/$/.test(k)));
});

test('DRF: registration ModelSerializer on the user model with a unique email → account-enumeration (register)', async () => {
  const { graph } = await buildGraph(tmpRepo(API));
  const w = graph.nodesOf('Weakness').filter((x) => x.kind === 'account-enumeration');
  assert.equal(w.length, 1);
  assert.equal(w[0].file, 'accounts/serializers.py');
  assert.equal(w[0].flowKind, 'register');
  assert.equal(w[0].flow, 'SignupSerializer');
  assert.match(w[0].message, /member with this email already exists/);
  // InviteSerializer redeclares `email`, so DRF adds no UniqueValidator: not reported.
  // Serializer fields are read / written through the API; create_user hashes the password (no raw password write).
  assert.ok(graph.edgesFrom('data:free_text', 'usedBy').some((e) => (e.columns || []).includes('bio')));
  assert.ok(!graph.edgesFrom('data:password', 'flowsTo').some((e) => e.python && e.to === 'store:column:member.password'));
  assert.ok(graph.edgesFrom('data:email', 'flowsTo').some((e) => e.python && e.to === 'store:column:member.email'));
});

test('settings secrets: literal SECRET_KEY / Flask config key, DEBUG and ALLOWED_HOSTS; env reads and dev settings are not reported', () => {
  const files = [
    { rel: 'proj/settings/production.py', kind: 'code', content: `INSTALLED_APPS = ['app']\nSECRET_KEY = "synthetic-test-value-0123456789abcdef"\nDEBUG = True\nALLOWED_HOSTS = ['*']\n` },
    { rel: 'proj/settings/dev.py', kind: 'code', content: `from .base import *\nINSTALLED_APPS = ['app']\nDEBUG = True\nSECRET_KEY = 'synthetic-dev-only-value-0123456789'\n` },
    { rel: 'other/settings.py', kind: 'code', content: `import os\nINSTALLED_APPS = []\nSECRET_KEY = os.environ['SECRET_KEY']\nDEBUG = os.environ.get('DEBUG') == '1'\n` },
    { rel: 'web/__init__.py', kind: 'code', content: `from flask import Flask\napp = Flask(__name__)\napp.config['SECRET_KEY'] = 'q8Zr3synthetic7Kp2Lm9'\n` },
    { rel: 'web/auth.py', kind: 'code', content: `import jwt\nfrom flask import current_app\ndef token(uid):\n    return jwt.encode({'id': uid}, current_app.config['SECRET_KEY'], algorithm='HS256')\n` },
    { rel: 'legacy/config.py', kind: 'code', content: `import os\nclass Config:\n    SECRET_KEY = os.environ.get('SECRET_KEY') or 'fallback-literal-value'\n` },
  ];
  const f = secretFindings(files);
  const locs = (f?.locations || []).map((l) => ({ at: `${l.file}:${l.line}`, label: l.label.en, snippet: l.snippet }));
  const at = locs.map((l) => l.at).sort();
  assert.deepEqual(at, ['proj/settings/production.py:2', 'proj/settings/production.py:3', 'proj/settings/production.py:4', 'web/__init__.py:3']);
  const flask = locs.find((l) => l.at === 'web/__init__.py:3');
  assert.match(flask.label, /SECRET_KEY is hard-coded/);
  assert.match(flask.label, /signs authentication tokens/);
  // Never the value: a random key shows no character of itself; a prefixed one keeps only its prefix.
  for (const l of locs) {
    assert.ok(!/q8Zr3synthetic7Kp2Lm9|0123456789abcdef/.test(`${l.label} ${l.snippet}`), l.at);
  }
  assert.match(flask.label, /<redacted>_\[REDACTED\]/);
  assert.match(locs.find((l) => l.at === 'proj/settings/production.py:3').label, /DEBUG = True/);
});
