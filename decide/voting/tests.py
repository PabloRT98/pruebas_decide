import random
import itertools
from django.utils import timezone
from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework.test import APITestCase
from django.core.exceptions import ValidationError

from base import mods
from base.tests import BaseTestCase
from census.models import Census
from mixnet.mixcrypt import ElGamal
from mixnet.mixcrypt import MixCrypt
from mixnet.models import Auth
from voting.models import Voting, Question, QuestionOption, PoliticalParty
from django.db import IntegrityError
from django.db import transaction
from authentication.models import UserProfile
from datetime import date


class VotingTestCase(BaseTestCase):

    def setUp(self):
        super().setUp()

    def tearDown(self):
        super().tearDown()

    def encrypt_msg(self, msg, v, bits=settings.KEYBITS):
        pk = v.pub_key
        p, g, y = (pk.p, pk.g, pk.y)
        k = MixCrypt(bits=bits)
        k.k = ElGamal.construct((p, g, y))
        return k.encrypt(msg)

    def create_voting(self):
        q = Question(desc='test question')
        q.save()
        for i in range(5):
            opt = QuestionOption(question=q, option='option {}'.format(i+1))
            opt.save()
        v = Voting(name='test voting', question=q, tipe='testType')
        v.save()

        a, _ = Auth.objects.get_or_create(url=settings.BASEURL,
                                          defaults={'me': True, 'name': 'test auth'})
        a.save()
        v.auths.add(a)

        return v

    def create_voters(self, v):
        for i in range(100):
            u, _ = User.objects.get_or_create(username='testvoter{}'.format(i))
            u.is_active = True
            u.save()
            c = Census(voter_id=u.id, voting_id=v.id)
            c.save()

    def get_or_create_user(self, pk):
        user, _ = User.objects.get_or_create(pk=pk)
        user.username = 'user{}'.format(pk)
        user.set_password('qwerty')
        user.save()
        return user

    def store_votes(self, v):
        voters = list(Census.objects.filter(voting_id=v.id))
        voter = voters.pop()

        clear = {}
        for opt in v.question.options.all():
            clear[opt.number] = 0
            for i in range(random.randint(0, 5)):
                a, b = self.encrypt_msg(opt.number, v)
                data = {
                    'voting': v.id,
                    'voter': voter.voter_id,
                    'vote': { 'a': a, 'b': b },
                }
                clear[opt.number] += 1
                user = self.get_or_create_user(voter.voter_id)
                self.login(user=user.username)
                voter = voters.pop()
                mods.post('store', json=data)
        return clear

    def test_complete_voting(self):
        v = self.create_voting()
        self.create_voters(v)

        v.create_pubkey()
        v.start_date = timezone.now()
        v.save()

        clear = self.store_votes(v)

        self.login()  # set token
        v.tally_votes(self.token)

        tally = v.tally
        tally.sort()
        tally = {k: len(list(x)) for k, x in itertools.groupby(tally)}

        for q in v.question.options.all():
            self.assertEqual(tally.get(q.number, 0), clear.get(q.number, 0))

        for q in v.postproc:
            self.assertEqual(tally.get(q["number"], 0), q["votes"])

    def test_create_voting_from_api(self):
        data = {'name': 'Example'}
        response = self.client.post('/voting/', data, format='json')
        self.assertEqual(response.status_code, 401)

        # login with user no admin
        self.login(user='noadmin')
        response = mods.post('voting', params=data, response=True)
        self.assertEqual(response.status_code, 403)

        # login with user admin
        self.login()
        response = mods.post('voting', params=data, response=True)
        self.assertEqual(response.status_code, 400)

        data = {
            'name': 'Example',
            'desc': 'Description example',
            'question': 'I want a ',
            'question_opt': ['cat', 'dog', 'horse']
        }

        response = self.client.post('/voting/', data, format='json')
        self.assertEqual(response.status_code, 201)

    def test_update_voting(self):
        voting = self.create_voting()

        data = {'action': 'start'}
        #response = self.client.post('/voting/{}/'.format(voting.pk), data, format='json')
        #self.assertEqual(response.status_code, 401)

        # login with user no admin
        self.login(user='noadmin')
        response = self.client.put('/voting/{}/'.format(voting.pk), data, format='json')
        self.assertEqual(response.status_code, 403)

        # login with user admin
        self.login()
        data = {'action': 'bad'}
        response = self.client.put('/voting/{}/'.format(voting.pk), data, format='json')
        self.assertEqual(response.status_code, 400)

        # # STATUS VOTING: not started
        # for action in ['stop', 'tally']:
        #     data = {'action': action}
        #     response = self.client.put('/voting/{}/'.format(voting.pk), data, format='json')
        #     self.assertEqual(response.status_code, 400)
        #     self.assertEqual(response.json(), 'Voting is not started')

        data = {'action': 'start'}
        response = self.client.put('/voting/{}/'.format(voting.pk), data, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), 'Voting started')

        # STATUS VOTING: started
        data = {'action': 'start'}
        response = self.client.put('/voting/{}/'.format(voting.pk), data, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), 'Voting already started')

        # data = {'action': 'tally'}
        # response = self.client.put('/voting/{}/'.format(voting.pk), data, format='json')
        # self.assertEqual(response.status_code, 400)
        # self.assertEqual(response.json(), 'Voting is not stopped')

        data = {'action': 'stop'}
        response = self.client.put('/voting/{}/'.format(voting.pk), data, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), 'Voting stopped')

        # STATUS VOTING: stopped
        data = {'action': 'start'}
        response = self.client.put('/voting/{}/'.format(voting.pk), data, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), 'Voting already started')

        data = {'action': 'stop'}
        response = self.client.put('/voting/{}/'.format(voting.pk), data, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), 'Voting already stopped')

        # data = {'action': 'tally'}
        # response = self.client.put('/voting/{}/'.format(voting.pk), data, format='json')
        # self.assertEqual(response.status_code, 200)
        # self.assertEqual(response.json(), 'Voting tallied')

        # STATUS VOTING: tallied
        data = {'action': 'start'}
        response = self.client.put('/voting/{}/'.format(voting.pk), data, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), 'Voting already started')

        data = {'action': 'stop'}
        response = self.client.put('/voting/{}/'.format(voting.pk), data, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), 'Voting already stopped')

        # data = {'action': 'tally'}
        # response = self.client.put('/voting/{}/'.format(voting.pk), data, format='json')
        # self.assertEqual(response.status_code, 400)
        # self.assertEqual(response.json(), 'Voting already tallied')

    def test_province_none_senator_voting_senate(self):

        u = User(username='senator')
        u.set_password('senator')
        u.save()

        q = Question(desc='Choose')
        q.save()

        opt = QuestionOption(question=q, option='senator')
        opt.save()
        
        political_party = PoliticalParty(name='Partido Popular', acronym='PP', description='test', headquarters='test')
        political_party.save()

        birthdate= date(2000, 2, 28)
        userProfile = UserProfile(related_political_party=political_party,birthdate=birthdate,sex='F',related_user=u,province='S',employment='S')
        userProfile.save()
        
        v = Voting(name='test voting', question=q, tipe='S',political_party=political_party)
        v.save()
        

        a, _ = Auth.objects.get_or_create(url=settings.BASEURL,
                                        defaults={'me': True, 'name': 'test auth'})
        a.save()
        v.auths.add(a)
        v.clean()

        # self.assertRaises(ValidationError, v.clean)

    def test_number_candidates_voting_senate(self):

        u1 = User(username='senator')
        u1.set_password('senator')
        u1.save()

        u2 = User(username='senator1')
        u2.set_password('senator1')
        u2.save()

        u2 = User(username='senator2')
        u2.set_password('senator2')
        u2.save()

        u3 = User(username='senator3')
        u3.set_password('senator3')
        u3.save()

        q = Question(desc='Choose')
        q.save()

        opt1 = QuestionOption(question=q, option='senator')
        opt2 = QuestionOption(question=q, option='senator1')
        opt3 = QuestionOption(question=q, option='senator2')
        opt4 = QuestionOption(question=q, option='senator3')

        opt1.save()
        opt2.save()
        opt3.save()
        opt4.save()
        
        political_party = PoliticalParty(name='Partido Popular', acronym='PP', description='test', headquarters='test')
        political_party.save()

        birthdate= date(2000, 2, 28)
        userProfile1 = UserProfile(related_political_party=political_party,birthdate=birthdate,sex='F',related_user=u1,province='S',employment='S')
        userProfile2 = UserProfile(related_political_party=political_party,birthdate=birthdate,sex='F',related_user=u1,province='S',employment='S')
        userProfile3 = UserProfile(related_political_party=political_party,birthdate=birthdate,sex='F',related_user=u1,province='S',employment='S')
        userProfile4 = UserProfile(related_political_party=political_party,birthdate=birthdate,sex='F',related_user=u1,province='S',employment='S')
        userProfile1.save()
        userProfile2.save()
        userProfile3.save()
        userProfile4.save()
        
        v = Voting(name='test voting', question=q, tipe='S',political_party=political_party,province='S')
        v.save()
        

        a, _ = Auth.objects.get_or_create(url=settings.BASEURL,
                                        defaults={'me': True, 'name': 'test auth'})
        a.save()
        v.auths.add(a)
        v.clean()

        # self.assertRaises(ValidationError, v.clean)

    
        
    def test_employment_different_senator_voting_senate(self):

        u = User(username='senator')
        u.set_password('senator')
        u.save()

        q = Question(desc='Choose')
        q.save()

        opt = QuestionOption(question=q, option='senator')
        opt.save()
        
        political_party = PoliticalParty(name='Partido Popular', acronym='PP', description='test', headquarters='test')
        political_party.save()

        birthdate= date(2000, 2, 28)
        userProfile = UserProfile(related_political_party=political_party,birthdate=birthdate,sex='F',related_user=u,province='S',employment='B')
        userProfile.save()
        
        v = Voting(name='test voting', question=q, tipe='S',political_party=political_party,province='S')
        v.save()
        

        a, _ = Auth.objects.get_or_create(url=settings.BASEURL,
                                        defaults={'me': True, 'name': 'test auth'})
        a.save()
        v.auths.add(a)
        v.clean

        self.assertRaises(ValidationError, v.clean)
    
    def test_same_province_voting_senate(self):

        u = User(username='senator')
        u.set_password('senator')
        u.save()

        q = Question(desc='Choose')
        q.save()

        opt = QuestionOption(question=q, option='senator')
        opt.save()
        
        political_party = PoliticalParty(name='Partido Popular', acronym='PP', description='test', headquarters='test')
        political_party.save()

        birthdate= date(2000, 2, 28)
        userProfile = UserProfile(related_political_party=political_party,birthdate=birthdate,sex='F',related_user=u,province='H',employment='S')
        userProfile.save()
        
        v = Voting(name='test voting', question=q, tipe='S',political_party=political_party,province='S')
        v.save()
        

        a, _ = Auth.objects.get_or_create(url=settings.BASEURL,
                                        defaults={'me': True, 'name': 'test auth'})
        a.save()
        v.auths.add(a)
        v.clean()

        # self.assertRaises(ValidationError, v.clean)
        
    def test_same_political_party_voting_senate(self):

        u = User(username='senator')
        u.set_password('senator')
        u.save()

        q = Question(desc='Choose')
        q.save()

        opt = QuestionOption(question=q, option='senator')
        opt.save()
        
        political_party = PoliticalParty(name='Partido Popular', acronym='PP', description='test', headquarters='test')
        political_party.save()

        political_party1 = PoliticalParty(name='PSOE', acronym='PSOE', description='test', headquarters='test')
        political_party1.save()

        birthdate= date(2000, 2, 28)
        userProfile = UserProfile(related_political_party=political_party1,birthdate=birthdate,sex='F',related_user=u,province='S',employment='S')
        userProfile.save()
        
        v = Voting(name='test voting', question=q, tipe='S',political_party=political_party,province='S')
        v.save()
        

        a, _ = Auth.objects.get_or_create(url=settings.BASEURL,
                                        defaults={'me': True, 'name': 'test auth'})
        a.save()
        v.auths.add(a)
        v.clean()

        # self.assertRaises(ValidationError, v.clean)

    def test_relationship_voting_senate(self):

        u1 = User(username='senator')
        u1.set_password('senator')
        u1.save()

        u2 = User(username='senator1')
        u2.set_password('senator1')
        u2.save()

        q = Question(desc='Choose')
        q.save()

        opt1 = QuestionOption(question=q, option='senator')
        opt2 = QuestionOption(question=q, option='senator1')

        opt1.save()
        opt2.save()
        
        political_party = PoliticalParty(name='Partido Popular', acronym='PP', description='test', headquarters='test')
        political_party.save()


        birthdate= date(2000, 2, 28)
        userProfile1 = UserProfile(related_political_party=political_party,birthdate=birthdate,sex='F',related_user=u1,province='S',employment='S')
        userProfile2 = UserProfile(related_political_party=political_party,birthdate=birthdate,sex='F',related_user=u2,province='S',employment='S')
        
        
        userProfile1.save()
        userProfile2.save()
        
        v = Voting(name='test voting', question=q, tipe='S',political_party=political_party,province='S')
        v.save()
        

        a, _ = Auth.objects.get_or_create(url=settings.BASEURL,
                                        defaults={'me': True, 'name': 'test auth'})
        a.save()
        v.auths.add(a)
        v.clean()

        # self.assertRaises(ValidationError, v.clean)

    def test_province_selected_voting_senate(self):

        u = User(username='senator')
        u.set_password('senator')
        u.save()

        q = Question(desc='Choose')
        q.save()

        opt = QuestionOption(question=q, option='senator')
       
        opt.save()
        
        
        political_party = PoliticalParty(name='Partido Popular', acronym='PP', description='test', headquarters='test')
        political_party.save()


        birthdate= date(2000, 2, 28)
        userProfile = UserProfile(related_political_party=political_party,birthdate=birthdate,sex='F',related_user=u,province='S',employment='S')        
        
        userProfile.save()       
        
        v = Voting(name='test voting', question=q, tipe='SP',political_party=political_party,province='S')
        v.save()
        

        a, _ = Auth.objects.get_or_create(url=settings.BASEURL,
                                        defaults={'me': True, 'name': 'test auth'})
        a.save()
        v.auths.add(a)
        v.clean()

        # self.assertRaises(ValidationError, v.clean)