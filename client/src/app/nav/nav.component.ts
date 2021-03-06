import { Component, OnInit } from '@angular/core';
import { AccountService } from '../_services/account.service';
import {MenuItem} from 'primeng/api'; 
import {SelectItem} from 'primeng/api';
import {SelectItemGroup} from 'primeng/api';
import { Observable } from 'rxjs';
import { User } from '../_models/user';

@Component({
  selector: 'app-nav',
  templateUrl: './nav.component.html',
  styleUrls: ['./nav.component.css']
})
export class NavComponent implements OnInit {
  model: any = {}


  constructor(public accountService: AccountService) { }

  ngOnInit(): void {

  }

  login() {
   this.accountService.login(this.model).subscribe(response => {
     console.log(response);

   }, error => {
    console.log(error);
   })
  }

  logout() {
    this.accountService.logout();
  }


}
